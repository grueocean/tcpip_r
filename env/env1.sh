# env1
#
#    d0 (172.20.10.100/24)       p0 (172.20.10.110/24)
#              |                           |
#              |                           |
#      |------|v                           v|--------|
#      | Dev0 |------------|   |------------| Tcpip0 |
#      |------|            |   |            |--------|
#                     l2-0 |   | l2-2
#                        |-------|
#                        | l2sw0 | <- Bridge
#                        |-------|
#                     l2-1 |   | l2-3
#      |------|            |   |            |--------|
#      | Dev1 |------------|   |------------| Tcpip1 |
#      |------|^                           ^|--------|
#              |                           |
#              |                           |
#    d1 (172.20.10.101/24)       p1 (172.20.10.111/24)
#

create() {
    set -eux

    ip netns add Dev0
    ip netns add Dev1
    ip netns add Tcpip0
    ip netns add Tcpip1
    brctl addbr l2sw0

    ip link add d0 netns Dev0 type veth peer name l2-0
    ip link add d1 netns Dev1 type veth peer name l2-1
    ip link add p0 netns Tcpip0 type veth peer name l2-2
    ip link add p1 netns Tcpip1 type veth peer name l2-3
    brctl addif l2sw0 l2-0
    brctl addif l2sw0 l2-1
    brctl addif l2sw0 l2-2
    brctl addif l2sw0 l2-3

    ip netns exec Tcpip0 ip addr add 172.20.10.110/24 dev p0
    ip netns exec Tcpip1 ip addr add 172.20.10.111/24 dev p1

    ip netns exec Dev0 ip link set lo up
    ip netns exec Dev0 ip link set d0 up

    ip netns exec Dev1 ip link set lo up
    ip netns exec Dev1 ip link set d1 up

    ip netns exec Tcpip0 ip link set lo up
    ip netns exec Tcpip0 ip link set p0 up

    ip netns exec Tcpip1 ip link set lo up
    ip netns exec Tcpip1 ip link set p1 up

    ip link set l2-0 up
    ip link set l2-1 up
    ip link set l2-2 up
    ip link set l2-3 up
    ip link set l2sw0 up

    # disable checksum offload
    ip netns exec Dev0 ethtool -K d0 rx off tx off
    ip netns exec Dev1 ethtool -K d1 rx off tx off
    ip netns exec Tcpip0 ethtool -K p0 rx off tx off
    ip netns exec Tcpip1 ethtool -K p1 rx off tx off
}

delete() {
    set -eux

    ip link delete l2-0
    ip link delete l2-1
    ip link delete l2-2
    ip link delete l2-3
    ip netns delete Dev0
    ip netns delete Dev1
    ip netns delete Tcpip0
    ip netns delete Tcpip1
    ip link set l2sw0 down
    brctl delbr l2sw0
}

pktcap() {
    ip netns exec Dev0 tcpdump -i d0 -w "pkt/Dev0-$(date +%Y-%m-%dT%H-%M-%S).pcap" >/dev/null 2>&1 &
    ip netns exec Dev1 tcpdump -i d1 -w "pkt/Dev1-$(date +%Y-%m-%dT%H-%M-%S).pcap" >/dev/null 2>&1 &
    ip netns exec Tcpip0 tcpdump -i p0 -w "pkt/Tcpip0-$(date +%Y-%m-%dT%H-%M-%S).pcap" >/dev/null 2>&1 &
    ip netns exec Tcpip1 tcpdump -i p1 -w "pkt/Tcpip1-$(date +%Y-%m-%dT%H-%M-%S).pcap" >/dev/null 2>&1 &
}

drop() {
    set -eux

    tc qdisc add dev l2-0 root netem loss $1%
    tc qdisc add dev l2-1 root netem loss $1%
    tc qdisc add dev l2-2 root netem loss $1%
    tc qdisc add dev l2-3 root netem loss $1%
}

clear() {
    set -eux

    tc qdisc del dev l2-0 root
    tc qdisc del dev l2-1 root
    tc qdisc del dev l2-2 root
    tc qdisc del dev l2-3 root
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
    drop)
        if [ $# -ne 2 ]; then
            echo "Option drop requires 2nd arg (drop rate)."
            exit 1
        fi
        drop $2
        ;;
    clear)
        clear
        ;;
    *)
        echo "Usage: $0 {create|delete|pktcap|drop|clear}"
        exit 1
        ;;
esac
