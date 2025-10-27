#!/usr/bin/env python3
"""
DNS Client with Recursive Mode Support
Reads PCAP files and resolves DNS queries with recursive_mode flag set to True
"""

import socket
import struct
import time
import json
import sys
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
            if dns_layer.qr == 0:  # Query
                query = dns_layer[DNSQR]
                domain = query.qname.decode('utf-8').rstrip('.')
                queries.append(domain)
                total_bytes += len(packet)
    
    return queries, total_bytes

def resolve_dns_recursive(domain, dns_server='10.0.0.5', recursive_mode=True):
    """
    Resolve DNS query with recursion desired flag
    
    Args:
        domain: Domain name to resolve
        dns_server: DNS server IP address
        recursive_mode: If True, set RD (Recursion Desired) flag
    
    Returns:
        Tuple of (ip_address, response_time_ms, recursion_available)
    """
    try:
        start_time = time.time()
        
        # Build DNS query header with RD flag if recursive_mode is True
        transaction_id = 0x1234
        if recursive_mode:
            flags = 0x0100  # RD (Recursion Desired) bit set
        else:
            flags = 0x0000  # No flags set (iterative query)
        
        # Header: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        query = struct.pack('!HHHHHH', transaction_id, flags, 1, 0, 0, 0)
        
        # Question section
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode('utf-8')
        query += b'\x00'
        
        # QTYPE (A record) and QCLASS (IN)
        query += struct.pack('!HH', 1, 1)
        
        # Send query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query, (dns_server, 5353))
        response, _ = sock.recvfrom(512)
        sock.close()
        
        response_time = (time.time() - start_time) * 1000
        
        # Parse response
        flags = struct.unpack('!H', response[2:4])[0]
        ancount = struct.unpack('!H', response[6:8])[0]
        
        # Check RA (Recursion Available) flag
        recursion_available = bool(flags & 0x0080)
        
        if ancount == 0:
            return None, response_time, recursion_available
        
        # Skip question section
        offset = 12
        while response[offset] != 0:
            offset += response[offset] + 1
        offset += 5  # Skip null byte + QTYPE + QCLASS
        
        # Parse answer section
        if response[offset] & 0xC0 == 0xC0:
            offset += 2  # Skip pointer
        
        offset += 8  # Skip TYPE, CLASS, TTL
        rdlength = struct.unpack('!H', response[offset:offset+2])[0]
        offset += 2
        
        if rdlength == 4:
            ip = '.'.join(str(b) for b in response[offset:offset+4])
            return ip, response_time, recursion_available
        
        return None, response_time, recursion_available
        
    except socket.timeout:
        return None, 5000, False  # Timeout after 5 seconds
    except Exception as e:
        print(f"Error resolving {domain}: {e}")
        return None, 0, False

def analyze_pcap_recursive(pcap_file, dns_server='10.0.0.5', recursive_mode=True):
    """
    Analyze PCAP file and resolve all DNS queries with recursive mode
    
    Args:
        pcap_file: Path to PCAP file
        dns_server: DNS server IP address
        recursive_mode: Whether to request recursive resolution
    
    Returns:
        Dictionary with statistics
    """
    print(f"\n{'='*80}")
    print(f"DNS CLIENT - RECURSIVE MODE ANALYSIS")
    print(f"{'='*80}")
    print(f"PCAP File: {pcap_file}")
    print(f"DNS Server: {dns_server}")
    print(f"Recursive Mode: {'ENABLED' if recursive_mode else 'DISABLED'}")
    print(f"{'='*80}\n")
    
    # Read PCAP
    print(f"Reading {pcap_file}...")
    domains, total_bytes = read_pcap(pcap_file)
    print(f"Found {len(domains)} DNS queries\n")
    
    if len(domains) == 0:
        print("No DNS queries found in PCAP file")
        return None
    
    # Resolve each domain
    print(f"{'Domain':<50} {'IP Address':<16} {'Latency (ms)':<12} {'RA'}")
    print("=" * 95)
    
    results = []
    total_latency = 0
    successful = 0
    failed = 0
    cache_hits = 0
    recursion_available_count = 0
    
    start_time = time.time()
    
    # Track domains for cache hit detection
    seen_domains = {}
    
    for i, domain in enumerate(domains, 1):
        ip, latency, recursion_available = resolve_dns_recursive(
            domain, dns_server, recursive_mode
        )
        
        # Check if this is likely a cache hit (very low latency)
        is_cache_hit = False
        if domain in seen_domains and latency < 5:  # < 5ms likely cache hit
            is_cache_hit = True
            cache_hits += 1
        else:
            seen_domains[domain] = True
        
        if recursion_available:
            recursion_available_count += 1
        
        ra_status = "✓" if recursion_available else "✗"
        
        if ip:
            status_str = f"{ip:<16} {latency:>8.2f} ms    {ra_status}"
            if is_cache_hit:
                status_str += " [CACHE]"
            print(f"{domain:<50} {status_str}")
            successful += 1
            total_latency += latency
            results.append({
                'query_num': i,
                'domain': domain,
                'ip': ip,
                'latency_ms': round(latency, 2),
                'recursion_available': recursion_available,
                'cache_hit': is_cache_hit,
                'status': 'SUCCESS'
            })
        else:
            print(f"{domain:<50} {'[FAILED]':<16} {latency:>8.2f} ms    {ra_status}")
            failed += 1
            total_latency += latency
            results.append({
                'query_num': i,
                'domain': domain,
                'ip': None,
                'latency_ms': round(latency, 2),
                'recursion_available': recursion_available,
                'cache_hit': False,
                'status': 'FAILED'
            })
    
    total_time = time.time() - start_time
    
    # Calculate statistics
    avg_latency = total_latency / len(domains) if domains else 0
    throughput = total_bytes / total_time if total_time > 0 else 0
    cache_hit_percentage = (cache_hits / len(domains) * 100) if domains else 0
    success_rate = (successful / len(domains) * 100) if domains else 0
    
    # Compile statistics
    stats = {
        'pcap_file': pcap_file.split('/')[-1],
        'dns_server': dns_server,
        'recursive_mode_enabled': recursive_mode,
        'recursion_available': recursion_available_count > 0,
        'total_queries': len(domains),
        'successful_resolutions': successful,
        'failed_resolutions': failed,
        'success_rate_percentage': round(success_rate, 2),
        'average_lookup_latency_ms': round(avg_latency, 2),
        'total_bytes': total_bytes,
        'total_time_seconds': round(total_time, 2),
        'average_throughput_bytes_per_sec': round(throughput, 2),
        'cache_hits': cache_hits,
        'cache_hit_percentage': round(cache_hit_percentage, 2),
        'queries_with_recursion_available': recursion_available_count,
        'results': results
    }
    
    # Print statistics
    print("\n" + "=" * 95)
    print("STATISTICS")
    print("=" * 95)
    print(f"Total Queries:              {stats['total_queries']}")
    print(f"Successful Resolutions:     {stats['successful_resolutions']} ({stats['success_rate_percentage']}%)")
    print(f"Failed Resolutions:         {stats['failed_resolutions']}")
    print(f"Average Lookup Latency:     {stats['average_lookup_latency_ms']} ms")
    print(f"Cache Hits:                 {stats['cache_hits']} ({stats['cache_hit_percentage']}%)")
    print(f"Total Bytes Transferred:    {stats['total_bytes']} bytes")
    print(f"Total Time:                 {stats['total_time_seconds']} seconds")
    print(f"Average Throughput:         {stats['average_throughput_bytes_per_sec']:.2f} bytes/sec")
    print(f"Recursion Available:        {'YES' if stats['recursion_available'] else 'NO'}")
    print(f"Queries w/ RA Flag:         {stats['queries_with_recursion_available']}")
    print("=" * 95)
    
    return stats

def main():
    if len(sys.argv) < 2:
        print("Usage: python dns_client_recursive.py <pcap_file> [dns_server] [--no-recursion]")
        print("\nExamples:")
        print("  python dns_client_recursive.py PCAP_1_H1_f.pcap")
        print("  python dns_client_recursive.py PCAP_1_H1_f.pcap 10.0.0.5")
        print("  python dns_client_recursive.py PCAP_1_H1_f.pcap 10.0.0.5 --no-recursion")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    dns_server = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else '10.0.0.5'
    recursive_mode = '--no-recursion' not in sys.argv
    
    # Analyze PCAP with recursive mode
    stats = analyze_pcap_recursive(pcap_file, dns_server, recursive_mode)
    
    if stats:
        # Save statistics to JSON file
        output_file = pcap_file.replace('.pcap', '_recursive_stats.json')
        with open(output_file, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"\nStatistics saved to: {output_file}")

if __name__ == '__main__':
    main()
