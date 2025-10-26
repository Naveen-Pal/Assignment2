#!/usr/bin/env python3
"""
DNS Client - Reads pcap file and resolves all DNS requests
"""

import socket
import struct
try:
    from scapy.all import rdpcap, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Error: scapy not installed. Install with: pip install scapy")
    exit(1)

def read_pcap(pcap_file):
    """Read pcap file and extract DNS queries"""
    queries = []
    packets = rdpcap(pcap_file)
    
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # Query
                query = dns_layer[DNSQR]
                domain = query.qname.decode('utf-8').rstrip('.')
                queries.append(domain)
    
    return list(set(queries))  # Remove duplicates

def resolve_dns(domain, dns_server='8.8.8.8'):
    """Resolve DNS query"""
    try:
        # Build DNS query
        query = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        
        # Add domain name
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode('utf-8')
        query += b'\x00'
        
        # Query type A and class IN
        query += struct.pack('!HH', 1, 1)
        
        # Send query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(query, (dns_server, 5353))
        response, _ = sock.recvfrom(512)
        sock.close()
        
        # Parse response
        ancount = struct.unpack('!H', response[6:8])[0]
        if ancount == 0:
            return None
        
        # Skip to answer section
        offset = 12
        while response[offset] != 0:
            offset += response[offset] + 1
        offset += 5
        
        # Skip name pointer
        if response[offset] & 0xC0 == 0xC0:
            offset += 2
        
        # Skip type, class, ttl
        offset += 8
        
        # Get data length
        rdlength = struct.unpack('!H', response[offset:offset+2])[0]
        offset += 2
        
        # Get IP address
        if rdlength == 4:
            ip = '.'.join(str(b) for b in response[offset:offset+4])
            return ip
        
        return response
        
    except:
        return "error"

def main():
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python dns_client.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Read pcap
    print(f"Reading {pcap_file}...")
    domains = read_pcap(pcap_file)
    print(f"Found {len(domains)} unique DNS queries\n")
    
    # Resolve each domain
    print("Domain → IP Address")
    print("=" * 60)
    
    for domain in domains:
        ip = resolve_dns(domain, "10.0.0.5")
        if ip:
            print(f"{domain:40} → {ip}")
        else:
            print(f"{domain:40} → [Failed]")

if __name__ == '__main__':
    main()