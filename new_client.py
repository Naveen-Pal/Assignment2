#!/usr/bin/env python3
import socket
import argparse
import dpkt
from datetime import datetime
from time import sleep
import dns.message
import dns.query

SERVER_HOST = "10.0.0.5"
SERVER_PORT = 53
SOCKET_TIMEOUT = 4  # seconds
INTER_PACKET_SLEEP = 0.1

def resolve(filename, server_host=SERVER_HOST, server_port=SERVER_PORT):
    # Read pcap file and extract DNS queries
    with open(filename, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        dns_packets = []

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue

                udp = ip.data
                # Check if UDP is DNS traffic
                if udp.sport == 53 or udp.dport == 53:
                    dns_pkt = dpkt.dns.DNS(udp.data)
                    if dns_pkt.qr == dpkt.dns.DNS_Q and dns_pkt.qd:
                        dns_packets.append(dns_pkt)
            except Exception:
                continue

    print(f"Found {len(dns_packets)} DNS queries in pcap")

    # Send each DNS query using dnspython
    for idx, dns_packet in enumerate(dns_packets):
        domain_name = dns_packet.qd[0].name if dns_packet.qd else "unknown"

        print(f"\n[{idx+1}] Querying {domain_name} ...")

        # Create dnspython DNS query
        try:
            outbound_query = dns.message.make_query(domain_name, dns.rdatatype.A)

            # set the recursive query flag to 1
            outbound_query.flags |= dns.flags.RD

            # Send query via UDP
            start_time = datetime.now()
            response = dns.query.udp(outbound_query, server_host, port=server_port, timeout=SOCKET_TIMEOUT)
            rtt = (datetime.now() - start_time).total_seconds()

            # Log results
            print(f"Response from {server_host}:{server_port}")
            for ans in response.answer:
                print(ans)
            print(f"RTT = {rtt:.3f} s")

        except Exception as e:
            print(f"Failed to resolve {domain_name}: {e}")

        sleep(INTER_PACKET_SLEEP)



def main():
    parser = argparse.ArgumentParser(description="Replay DNS packets from pcap to UDP server and measure responses")
    parser.add_argument("--pcap", required=True, help="PCAP filename to read DNS queries from")
    parser.add_argument("--hostname", required=True, help="Output filename to write results (kept name 'hostname' for compatibility)")
    parser.add_argument("--server-host", default=SERVER_HOST, help="Server IP to send DNS payloads to")
    parser.add_argument("--server-port", type=int, default=SERVER_PORT, help="Server UDP port")
    args = parser.parse_args()

    resolve(args.pcap, server_host=args.server_host, server_port=args.server_port)


if __name__ == "__main__":
    main()