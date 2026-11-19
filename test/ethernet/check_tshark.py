# Compare eth_pcaps.py output with tshark's decode, so a generator bug and a parser bug can't
# agree.  Usage: check_tshark.py <pcap> <manifest.json> [tshark binary]
# Reads the pcap only; frames marked hostile are expected to be malformed and are skipped,
# every other frame must decode without a malformed or error-level expert item.
import json, subprocess, sys

FIELDS = ["frame.number", "eth.src", "eth.dst", "sll.src.eth", "ieee8021ad.id", "vlan.id", "ip.src", "ip.dst",
        "ip.hdr_len", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "tcp.flags",
        "udp.srcport", "udp.dstport", "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
        "dhcp.option.dhcp", "dhcp.option.hostname", "dhcp.option.vendor_class_id",
        "dhcp.option.request_list_item", "dhcp.fqdn.name", "dhcp.ip.your", "dhcpv6.msgtype",
        "dhcpv6.client_domain", "_ws.malformed", "_ws.expert.severity", "ipv6.fraghdr.offset",
        "ipv6.nxt"]

def main():
    pcap, manifest = sys.argv[1], sys.argv[2]
    tshark = sys.argv[3] if len(sys.argv) > 3 else "/usr/bin/tshark"
    m = json.load(open(manifest))
    dlt = m["dlt"]
    cmd = [tshark, "-n", "-r", pcap, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
            "-E", "aggregator=,", "-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
            "-o", "tcp.check_checksum:TRUE", "-o", "ipv6.defragment:FALSE"]
    for f in FIELDS:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, check=True, stdin=subprocess.DEVNULL)
    rows = [l.split("\t") for l in res.stdout.decode("utf-8", "replace").splitlines()]
    if len(rows) != len(m["frames"]):
        print("FAIL frame count: tshark %d, manifest %d" % (len(rows), len(m["frames"])))
        return 1
    bad = 0
    checked = 0
    for row, want in zip(rows, m["frames"]):
        got = dict(zip(FIELDS, row + [""] * (len(FIELDS) - len(row))))
        n = got["frame.number"]
        if not want or want.get("hostile"):
            continue
        errs = []
        def eq(k, v):
            if got[k] != v:
                errs.append("%s: tshark %r, want %r" % (k, got[k], v))
        # severity 8388608 = error; checksums failing would show up here too
        sev = [int(s) for s in got["_ws.expert.severity"].split(",") if s]
        if got["_ws.malformed"] or any(s >= 8388608 for s in sev):
            if not (want.get("deep_tags") or want.get("deep_ext")):
                errs.append("malformed or error expert info")
        if dlt == 1:
            eq("eth.src", want["src"])
            if "dst" in want:
                eq("eth.dst", want["dst"])
        else:
            eq("sll.src.eth", want["src"])
        if "vlans" in want:
            # tshark names an 802.1ad outer tag ieee8021ad, 0x8100 and 0x9100 tags vlan
            tags = ",".join(x for x in (got["ieee8021ad.id"], got["vlan.id"]) if x)
            if tags != ",".join(str(v) for v in want["vlans"]):
                errs.append("tags: tshark %r, want %r" % (tags, want["vlans"]))
        got["dhcpv6.client_domain"] = got["dhcpv6.client_domain"].rstrip(".")
        simple = {"ip_src": "ip.src", "ip_dst": "ip.dst", "ip_hl": "ip.hdr_len", "ipv6_src": "ipv6.src",
                "ipv6_dst": "ipv6.dst", "tcp_sport": "tcp.srcport", "tcp_dport": "tcp.dstport",
                "udp_sport": "udp.srcport", "udp_dport": "udp.dstport", "arp_op": "arp.opcode",
                "arp_spa": "arp.src.proto_ipv4", "arp_tpa": "arp.dst.proto_ipv4",
                "dhcp_type": "dhcp.option.dhcp", "dhcp_hostname": "dhcp.option.hostname",
                "dhcp_vendor": "dhcp.option.vendor_class_id", "dhcp_fqdn": "dhcp.fqdn.name",
                "dhcp_yiaddr": "dhcp.ip.your", "dhcpv6_type": "dhcpv6.msgtype",
                "dhcpv6_fqdn": "dhcpv6.client_domain"}
        for k, f in simple.items():
            if k in want:
                eq(f, str(want[k]))
        if "tcp_flags" in want:
            v = got["tcp.flags"]
            if not v or int(v, 16) != want["tcp_flags"]:
                errs.append("tcp.flags: tshark %r, want %#x" % (v, want["tcp_flags"]))
        if "dhcp_prl" in want:
            eq("dhcp.option.request_list_item", ",".join(str(v) for v in want["dhcp_prl"]))
        checked += 1
        if errs:
            bad += 1
            print("frame %s: %s" % (n, "; ".join(errs)))
    print("%s: %d frames, %d compared, %d mismatched" % (pcap, len(rows), checked, bad))
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
