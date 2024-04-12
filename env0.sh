# env0
#
#            d0 (w/o ip directly use as 172.20.10.100/24)
#            |
#            |               p0 (172.20.10.110/24)
#            |               |
#    |------|v  (veth pair)  v|--------|
#    | Dev0 |-----------------| Tcpip0 |
#    |------|                 |--------|

create() {
    set -eux

    ip netns add Dev0
    ip netns add Tcpip0

    ip link add p0 netns Tcpip0 type veth peer name d0 netns Dev0
    ip netns exec Tcpip0 ip addr add 172.20.10.110/24 dev p0

    ip netns exec Dev0 ip link set lo up
    ip netns exec Dev0 ip link set d0 up

    ip netns exec Tcpip0 ip link set lo up
    ip netns exec Tcpip0 ip link set p0 up
}

delete() {
    set -eux

    ip netns delete Dev0
    ip netns delete Tcpip0
}

pktcap() {
    ip netns exec Dev0 tcpdump -i d0 -w "pkt/Dev0-$(date +%Y-%m-%dT%H-%M-%S).pcap" >/dev/null 2>&1 &
    ip netns exec Tcpip0 tcpdump -i p0 -w "pkt/Tcpip0-$(date +%Y-%m-%dT%H-%M-%S).pcap" >/dev/null 2>&1 &
}

case "$1" in
    create)
        create
        ;;
    delete)
        delete
        ;;
    pktcap)
        pktcap
        ;;
    *)
        echo "Usage: $0 {create|delete|pktcap}"
        exit 1
        ;;
esac
