# Synthetic Wi-Fi and Ethernet pcaps for links refused at a cap and retried once there's room.
# Every MAC is 02:xx (locally administered), IPv4 198.18/15.
#
# Usage: cap_pcaps.py <edges|index> <wifi.pcap> <wire.pcap> [--t0 S] [--t-old S]
#
#   edges  40 associated Wi-Fi clients, all also on the wire: group A (02:00:00:00:a5:xx) first,
#          dated --t-old on the wire, then group B (02:00:00:00:b5:xx) dated --t0.  Run with
#          entity_max_edges=20 and tracker_device_timeout: A takes every link, B is refused,
#          then A's wired records expire and B must be linked.
#   index  60 associated Wi-Fi clients, each sending one ARP on the wire and then a second.
#          Run with wired_max_devices=10 and wired_new_device_rate=0: the second pass evicts
#          the oldest records to admit the refused ones, so many more MACs arrive in one
#          second than the link index holds, and the last 10 left must be linked.
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ethernet"))
import wifi_link_pcaps as w  # noqa: E402
from eth_pcaps import eth, arp, BC  # noqa: E402

def client_mac(prefix, j):
    return bytes([0x02, 0x00, 0x00, 0x00, prefix, j])

def ip_of(prefix, j):
    return "198.18.%d.%d" % (prefix, j + 1)

def wire_arp(m, ip):
    return eth(BC, m, 0x0806, arp(2, m, ip, BC, ip))

def air_clients(air, macs_ips):
    seq = 0
    for b in range(4):
        seq += 1
        air.add(w.beacon(seq))
    for m, ip in macs_ips:
        seq += 1
        air.add(w.assoc_req(m, seq), dt=200)
        seq += 1
        air.add(w.to_ds(m, BC, ip, "198.19.255.255", seq), dt=200)

def main():
    a = sys.argv[1:]
    if len(a) < 3 or a[0] not in ("edges", "index"):
        sys.exit("usage: cap_pcaps.py edges|index wifi.pcap wire.pcap [--t0 S] [--t-old S]")
    opts = {"--t0": 1_790_000_000, "--t-old": 1_789_000_000}
    i = 3
    while i < len(a):
        if a[i] not in opts or i + 1 >= len(a):
            sys.exit("unknown or incomplete option %s" % a[i])
        opts[a[i]] = int(a[i + 1])
        i += 2

    air = w.pcap(a[1], 105, opts["--t0"])

    if a[0] == "edges":
        group_a = [(client_mac(0xa5, j), ip_of(0xa5, j)) for j in range(20)]
        group_b = [(client_mac(0xb5, j), ip_of(0xb5, j)) for j in range(20)]
        air_clients(air, group_a + group_b)
        wire = w.pcap(a[2], 1, opts["--t-old"])
        for m, ip in group_a:
            wire.add(wire_arp(m, ip), dt=400)
        # The same file, dated now from here on
        wire.t0 = opts["--t0"]
        wire.t = 0
        for m, ip in group_b:
            wire.add(wire_arp(m, ip), dt=400)
    else:
        hosts = [(client_mac(0xc6, j), ip_of(0xc6, j)) for j in range(60)]
        air_clients(air, hosts)
        wire = w.pcap(a[2], 1, opts["--t0"])
        for p in range(2):
            for m, ip in hosts:
                wire.add(wire_arp(m, ip), dt=400)

    air.close()
    wire.close()

if __name__ == "__main__":
    main()
