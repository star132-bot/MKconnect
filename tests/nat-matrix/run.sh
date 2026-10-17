#!/usr/bin/env bash
# NAT 矩阵测试。
#
# 用 Linux 网络命名空间搭一个小型“互联网”：两台主机各自躲在一台 NAT 路由器后面，
# 公网上有一台自建中继。逐一测试 4×4 种 NAT 组合：能否连通、最终走直连还是中继。
#
#   主机 A ── NAT 路由器 A ──┐
#                            ├── 公网交换机 ── 中继 203.0.113.10
#   主机 B ── NAT 路由器 B ──┘
#
# NAT 类型：
#   none        无 NAT，主机地址可从公网直接访问
#   fullcone    完全锥形：端口映射与目的地无关，任何外部地址都能发进来
#   restricted  端口受限锥形：映射与目的地无关，只放行已联系过的地址和端口（家用路由器常见）
#   symmetric   对称型：每个目的地分配不同的随机端口（企业网和部分运营商常见）
#
# 需要 root，以及 iproute2、nftables、openssl、jq、mk、iroh-relay。
# 用法：sudo tests/nat-matrix/run.sh [mk 路径] [iroh-relay 路径]
# 环境变量：
#   TYPES       要测的 NAT 类型，默认全部四种
#   PING_COUNT  每个组合测延迟的次数，每秒一次，默认 15
#   DELAY_MS    每台路由器到公网的单向延迟，默认 10
#   OUT         结果目录，默认 nat-matrix-results
set -euo pipefail

MK=$(realpath "${1:-target/release/mk}")
RELAY_BIN=$(realpath "${2:-$(command -v iroh-relay)}")
TYPES=${TYPES:-"none fullcone restricted symmetric"}
PING_COUNT=${PING_COUNT:-15}
DELAY_MS=${DELAY_MS:-10}
OUT=$(realpath -m "${OUT:-nat-matrix-results}")
RELAY_IP=203.0.113.10
P=mkt

WORK=$(mktemp -d)
mkdir -p "$OUT"
RESULTS="$OUT/results.jsonl"
: > "$RESULTS"

ns() {
    local name=$1
    shift
    ip netns exec "$P-$name" "$@"
}

cleanup() {
    local name
    for name in $(ip netns list 2>/dev/null | awk '{print $1}' | grep "^$P-" || true); do
        ip netns pids "$name" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$name" 2>/dev/null || true
    done
}
trap 'cleanup; rm -rf "$WORK"' EXIT

side_index() { [[ $1 == a ]] && echo 1 || echo 2; }
wan_ip() { echo "203.0.113.$((20 * $(side_index "$1")))"; }
host_ip() { echo "10.$(side_index "$1").0.2"; }

# 路由器上的 nftables 规则，决定 NAT 类型。
nat_rules() {
    local type=$1 host=$2
    local filter_strict="table inet mkfilter {
        chain forward {
            type filter hook forward priority 0; policy drop;
            ct state established,related accept
            iifname \"lan\" accept
        }
    }"
    case $type in
    none)
        echo "table inet mkfilter { chain forward { type filter hook forward priority 0; policy accept; } }"
        ;;
    fullcone)
        cat <<EOF
table ip mknat {
    chain post { type nat hook postrouting priority 100; oifname "wan" masquerade; }
    chain pre { type nat hook prerouting priority -100; iifname "wan" meta l4proto udp dnat to $host; }
}
table inet mkfilter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iifname "lan" accept
        iifname "wan" ip daddr $host meta l4proto udp accept
    }
}
EOF
        ;;
    restricted)
        echo "table ip mknat { chain post { type nat hook postrouting priority 100; oifname \"wan\" masquerade; } }"
        echo "$filter_strict"
        ;;
    symmetric)
        echo "table ip mknat { chain post { type nat hook postrouting priority 100; oifname \"wan\" masquerade fully-random; } }"
        echo "$filter_strict"
        ;;
    *)
        echo "未知 NAT 类型：$type" >&2
        exit 2
        ;;
    esac
}

setup_topology() {
    local type_a=$1 type_b=$2
    cleanup

    ip netns add "$P-inet"
    ns inet ip link set lo up
    ns inet ip link add br0 type bridge
    ns inet ip link set br0 up

    ip netns add "$P-relay"
    ns inet ip link add up-relay type veth peer name wan netns "$P-relay"
    ns inet ip link set up-relay master br0 up
    ns relay ip link set lo up
    ns relay ip addr add "$RELAY_IP/24" dev wan
    ns relay ip link set wan up

    local side type idx
    for side in a b; do
        [[ $side == a ]] && type=$type_a || type=$type_b
        idx=$(side_index "$side")

        ip netns add "$P-rtr$side"
        ip netns add "$P-host$side"

        ns inet ip link add "up-$side" type veth peer name wan netns "$P-rtr$side"
        ns inet ip link set "up-$side" master br0 up
        if ((DELAY_MS > 0)); then
            ns inet tc qdisc add dev "up-$side" root netem delay "${DELAY_MS}ms"
        fi

        ns "rtr$side" ip link set lo up
        ns "rtr$side" ip addr add "$(wan_ip "$side")/24" dev wan
        ns "rtr$side" ip link set wan up
        ns "rtr$side" sysctl -qw net.ipv4.ip_forward=1
        ns "rtr$side" ip link add lan type veth peer name eth0 netns "$P-host$side"
        ns "rtr$side" ip addr add "10.$idx.0.1/24" dev lan
        ns "rtr$side" ip link set lan up

        ns "host$side" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
        ns "host$side" ip link set lo up
        ns "host$side" ip addr add "$(host_ip "$side")/24" dev eth0
        ns "host$side" ip link set eth0 up
        ns "host$side" ip route add default via "10.$idx.0.1"

        nat_rules "$type" "$(host_ip "$side")" | ns "rtr$side" nft -f -
    done

    # 无 NAT 的一侧，其内网地址就是“公网地址”，其他公网节点要能路由过去。
    for side in a b; do
        [[ $side == a ]] && type=$type_a || type=$type_b
        [[ $type == none ]] || continue
        idx=$(side_index "$side")
        local other=b
        [[ $side == b ]] && other=a
        ns relay ip route add "10.$idx.0.0/24" via "$(wan_ip "$side")"
        ns "rtr$other" ip route add "10.$idx.0.0/24" via "$(wan_ip "$side")"
    done
}

make_relay_certs() {
    local dir=$WORK/tls
    mkdir -p "$dir"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
        -subj "/CN=mkconnect-test-ca" -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -subj "/CN=$RELAY_IP" -keyout "$dir/relay.key" -out "$dir/relay.csr" 2>/dev/null
    printf 'subjectAltName=IP:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' \
        "$RELAY_IP" >"$dir/ext.cnf"
    openssl x509 -req -in "$dir/relay.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
        -CAcreateserial -days 2 -extfile "$dir/ext.cnf" -out "$dir/relay.crt" 2>/dev/null

    cat >"$WORK/relay.toml" <<EOF
http_bind_addr = "$RELAY_IP:80"
enable_quic_addr_discovery = true

[tls]
cert_mode = "Manual"
manual_cert_path = "$dir/relay.crt"
manual_key_path = "$dir/relay.key"
https_bind_addr = "$RELAY_IP:443"
EOF
}

mk_on() {
    local side=$1
    shift
    ns "host$side" env MK_HOME="$WORK/home-$side" "$MK" \
        --relay "https://$RELAY_IP" --relay-ca "$WORK/tls/ca.crt" --json "$@"
}

wait_for() {
    local file=$1 pattern=$2 tries=${3:-50}
    while ((tries-- > 0)); do
        grep -q "$pattern" "$file" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

run_case() {
    local type_a=$1 type_b=$2
    local case_dir=$OUT/logs/$type_a-$type_b
    mkdir -p "$case_dir"
    setup_topology "$type_a" "$type_b"

    ns relay "$RELAY_BIN" --config-path "$WORK/relay.toml" >"$case_dir/relay.log" 2>&1 &
    sleep 1

    mk_on b listen --dir "$WORK/recv-b" >"$case_dir/listen.log" 2>"$case_dir/listen.err" &
    if ! wait_for "$case_dir/listen.log" '"event":"bound"'; then
        echo "  B 未能启动" >&2
    fi
    local ticket
    ticket=$(jq -r 'select(.event=="bound") | .ticket' "$case_dir/listen.log" | head -1)

    local rc=0
    mk_on a ping "$ticket" -c "$PING_COUNT" --interval-ms 1000 \
        >"$case_dir/ping.log" 2>"$case_dir/ping.err" || rc=$?

    local setup_ms summary
    setup_ms=$(jq -r 'select(.event=="connected") | .setup_ms' "$case_dir/ping.log" | head -1)
    summary=$(jq -c 'select(.event=="ping_summary")' "$case_dir/ping.log" | tail -1)
    jq -nc \
        --arg a "$type_a" --arg b "$type_b" --argjson rc "$rc" \
        --arg setup "${setup_ms:-}" --argjson summary "${summary:-null}" \
        '{a: $a, b: $b, ok: ($rc == 0 and $summary != null and $summary.received > 0),
          final_path: ($summary.final_path // "none"),
          setup_ms: (if $setup == "" then null else ($setup | tonumber) end),
          avg_ms: $summary.avg_ms, received: ($summary.received // 0), sent: ($summary.sent // 0)}' \
        >>"$RESULTS"
    tail -1 "$RESULTS"
}

write_summary() {
    local md=$OUT/summary.md
    {
        echo "## NAT 矩阵测试结果"
        echo
        echo "行为主机 A（发起方），列为主机 B（等待方）。每格为最终路径和平均往返延迟。"
        echo
        printf '| A \\ B |'
        for b in $TYPES; do printf ' %s |' "$b"; done
        echo
        printf '| --- |'
        for _ in $TYPES; do printf ' --- |'; done
        echo
        for a in $TYPES; do
            printf '| %s |' "$a"
            for b in $TYPES; do
                jq -r --arg a "$a" --arg b "$b" '
                    select(.a == $a and .b == $b) |
                    if .ok then
                        (if .final_path == "direct" then "直连" else "中继" end)
                        + " " + ((.avg_ms // 0) | floor | tostring) + " ms"
                    else "失败" end' "$RESULTS" | tr -d '\n' | sed 's/^/ /;s/$/ |/'
            done
            echo
        done
        echo
        jq -rs '"连通 \(map(select(.ok)) | length) / \(length)，其中直连 \(map(select(.ok and .final_path == "direct")) | length)。"' "$RESULTS"
    } >"$md"
    cat "$md"
    if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
        cat "$md" >>"$GITHUB_STEP_SUMMARY"
    fi
}

main() {
    [[ $EUID -eq 0 ]] || {
        echo "需要 root 权限" >&2
        exit 1
    }
    make_relay_certs

    local a_id
    a_id=$(MK_HOME="$WORK/home-a" "$MK" id)
    MK_HOME="$WORK/home-b" "$MK" id >/dev/null
    MK_HOME="$WORK/home-b" "$MK" trust add "$a_id" >/dev/null

    local a b
    for a in $TYPES; do
        for b in $TYPES; do
            echo "== A=$a B=$b"
            run_case "$a" "$b"
        done
    done

    write_summary
    # 发布关口：所有组合都必须连通（直连或中继均可）。
    jq -se 'all(.ok)' "$RESULTS" >/dev/null
}

main "$@"
