#!/usr/bin/env python3
"""
DNS Client - Reads pcap file and resolves all DNS requests
"""

import socket
import struct
import time
import json
try:
    from scapy.all import rdpcap, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Error: scapy not installed. Install with: pip install scapy")
    exit(1)

def read_pcap(pcap_file):
    """Read pcap file and extract DNS queries with total bytes"""
    queries = []
    total_bytes = 0
    packets = rdpcap(pcap_file)
    
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:
                query = dns_layer[DNSQR]
                domain = query.qname.decode('utf-8').rstrip('.')
                queries.append(domain)
                total_bytes += len(packet)
    
    return queries, total_bytes

def resolve_dns(domain, dns_server='10.0.0.5'):
    """Resolve DNS query"""
    try:
        query = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode('utf-8')
        query += b'\x00'
        query += struct.pack('!HH', 1, 1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(query, (dns_server, 5353))
        response, _ = sock.recvfrom(512)
        sock.close()
        
        ancount = struct.unpack('!H', response[6:8])[0]
        if ancount == 0:
            return None
        
        offset = 12
        while response[offset] != 0:
            offset += response[offset] + 1
        offset += 5
        
        if response[offset] & 0xC0 == 0xC0:
            offset += 2
        
        offset += 8
        rdlength = struct.unpack('!H', response[offset:offset+2])[0]
        offset += 2
        
        if rdlength == 4:
            ip = '.'.join(str(b) for b in response[offset:offset+4])
            return ip
        
        return None
    except:
        return None

def main():
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python dns_client.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Read pcap
    print(f"Reading {pcap_file}...")
    domains, total_bytes = read_pcap(pcap_file)
    print(f"Found {len(domains)} DNS queries\n")
    
    # Resolve each domain
    print("Domain -> IP Address")
    print("=" * 60)
    
    results = []
    total_latency = 0
    successful = 0
    failed = 0
    start_time = time.time()
    
    for domain in domains:
        query_start = time.time()
        ip = resolve_dns(domain, "10.0.0.5")
        query_time = (time.time() - query_start) * 1000
        
        if ip:
            print(f"{domain:40} -> {ip}")
            successful += 1
            total_latency += query_time
            results.append({'domain': domain, 'ip': ip, 'latency_ms': round(query_time, 2), 'status': 'SUCCESS'})
        else:
            print(f"{domain:40} -> [Failed]")
            failed += 1
            results.append({'domain': domain, 'ip': None, 'latency_ms': round(query_time, 2), 'status': 'FAILED'})
    
    total_time = time.time() - start_time
    
    # Statistics
    stats = {
        'host': pcap_file.split('/')[-1].replace('.pcap', ''),
        'total_queries': len(domains),
        'successful_resolutions': successful,
        'failed_resolutions': failed,
        'average_lookup_latency_ms': round(total_latency / len(domains), 2) if domains else 0,
        'total_bytes': total_bytes,
        'average_throughput_bytes_per_sec': round(total_bytes / total_time, 2) if total_time > 0 else 0,
        'results': results
    }
    
    # Print statistics
    print("\n" + "=" * 60)
    print("STATISTICS")
    print("=" * 60)
    print(f"Total Queries: {stats['total_queries']}")
    print(f"Successful: {stats['successful_resolutions']}")
    print(f"Failed: {stats['failed_resolutions']}")
    print(f"Avg Lookup Latency: {stats['average_lookup_latency_ms']} ms")
    print(f"Total Bytes: {stats['total_bytes']} bytes")
    print(f"Avg Throughput: {stats['average_throughput_bytes_per_sec']} bytes/sec")
    
    # Save to JSON
    output_file = pcap_file.replace('.pcap', '_stats.json')
    with open(output_file, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"\nSaved to: {output_file}")

if __name__ == '__main__':
    main()