#!/usr/bin/env python3
"""
DNS Cache Performance Analyzer
Analyzes caching performance of the DNS resolver
Records: average lookup latency, throughput, successful queries, cache hit %, failed resolutions
"""

import socket
import struct
import time
import json
import sys
import os
from datetime import datetime

try:
    from scapy.all import rdpcap, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Error: scapy not installed. Install with: pip install scapy")
    exit(1)

class DNSCacheAnalyzer:
    """Analyzes DNS cache performance"""
    
    def __init__(self, dns_server='10.0.0.5', port=5353):
        self.dns_server = dns_server
        self.port = port
        self.results = []
        self.cache_threshold_ms = 5.0  # Queries < 5ms are likely cache hits
        
    def read_pcap(self, pcap_file):
        """Read PCAP file and extract DNS queries"""
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
    
    def resolve_dns(self, domain, recursive_mode=True):
        """
        Resolve DNS query and measure response time
        
        Returns:
            Tuple of (ip_address, latency_ms, from_cache)
        """
        try:
            start_time = time.time()
            
            # Build DNS query
            transaction_id = 0x1234
            flags = 0x0100 if recursive_mode else 0x0000  # RD flag
            
            query = struct.pack('!HHHHHH', transaction_id, flags, 1, 0, 0, 0)
            
            for part in domain.split('.'):
                query += bytes([len(part)]) + part.encode('utf-8')
            query += b'\x00'
            query += struct.pack('!HH', 1, 1)
            
            # Send query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(query, (self.dns_server, self.port))
            response, _ = sock.recvfrom(512)
            sock.close()
            
            latency = (time.time() - start_time) * 1000
            
            # Parse response
            ancount = struct.unpack('!H', response[6:8])[0]
            
            if ancount == 0:
                return None, latency, False
            
            # Skip question section
            offset = 12
            while response[offset] != 0:
                offset += response[offset] + 1
            offset += 5
            
            # Parse answer
            if response[offset] & 0xC0 == 0xC0:
                offset += 2
            
            offset += 8
            rdlength = struct.unpack('!H', response[offset:offset+2])[0]
            offset += 2
            
            if rdlength == 4:
                ip = '.'.join(str(b) for b in response[offset:offset+4])
                # Cache detection: very fast responses are likely from cache
                from_cache = latency < self.cache_threshold_ms
                return ip, latency, from_cache
            
            return None, latency, False
            
        except socket.timeout:
            return None, 5000, False
        except Exception as e:
            return None, 0, False
    
    def analyze_pcap(self, pcap_file, recursive_mode=True, run_twice=True):
        """
        Analyze PCAP file with cache performance metrics
        
        Args:
            pcap_file: Path to PCAP file
            recursive_mode: Whether to use recursive DNS queries
            run_twice: If True, run queries twice to test cache performance
        """
        print(f"\n{'='*90}")
        print(f"DNS CACHE PERFORMANCE ANALYZER")
        print(f"{'='*90}")
        print(f"PCAP File: {pcap_file}")
        print(f"DNS Server: {self.dns_server}:{self.port}")
        print(f"Recursive Mode: {'ENABLED' if recursive_mode else 'DISABLED'}")
        print(f"Cache Test: {'ENABLED (2 runs)' if run_twice else 'DISABLED (1 run)'}")
        print(f"{'='*90}\n")
        
        # Read PCAP
        domains, total_bytes = self.read_pcap(pcap_file)
        
        if len(domains) == 0:
            print("No DNS queries found in PCAP file")
            return None
        
        print(f"Found {len(domains)} DNS queries")
        print(f"Total packet size: {total_bytes} bytes\n")
        
        # Statistics
        stats = {
            'pcap_file': pcap_file,
            'total_queries': 0,
            'successful_resolutions': 0,
            'failed_resolutions': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'total_latency_ms': 0,
            'total_bytes': total_bytes,
            'runs': []
        }
        
        # Run queries (once or twice for cache testing)
        runs = 2 if run_twice else 1
        
        for run_num in range(1, runs + 1):
            print(f"\n{'='*90}")
            print(f"RUN {run_num}/{runs}" + (" - Testing Cache Performance" if run_num == 2 else " - Initial Resolution"))
            print(f"{'='*90}")
            print(f"{'#':<5} {'Domain':<45} {'IP Address':<16} {'Latency':<12} {'Source'}")
            print("=" * 90)
            
            run_stats = {
                'run_number': run_num,
                'total_queries': 0,
                'successful': 0,
                'failed': 0,
                'cache_hits': 0,
                'total_latency_ms': 0,
                'queries': []
            }
            
            start_time = time.time()
            
            for i, domain in enumerate(domains, 1):
                ip, latency, from_cache = self.resolve_dns(domain, recursive_mode)
                
                run_stats['total_queries'] += 1
                
                if ip:
                    source = "CACHE" if from_cache else "EXTERNAL"
                    if from_cache:
                        run_stats['cache_hits'] += 1
                    
                    print(f"{i:<5} {domain:<45} {ip:<16} {latency:>7.2f} ms   {source}")
                    run_stats['successful'] += 1
                    run_stats['total_latency_ms'] += latency
                    
                    run_stats['queries'].append({
                        'domain': domain,
                        'ip': ip,
                        'latency_ms': round(latency, 3),
                        'from_cache': from_cache,
                        'status': 'SUCCESS'
                    })
                else:
                    print(f"{i:<5} {domain:<45} {'[FAILED]':<16} {latency:>7.2f} ms   ERROR")
                    run_stats['failed'] += 1
                    run_stats['total_latency_ms'] += latency
                    
                    run_stats['queries'].append({
                        'domain': domain,
                        'ip': None,
                        'latency_ms': round(latency, 3),
                        'from_cache': False,
                        'status': 'FAILED'
                    })
                
                # Small delay to not overwhelm the server
                time.sleep(0.01)
            
            end_time = time.time()
            run_stats['total_time_seconds'] = round(end_time - start_time, 3)
            
            # Calculate run statistics
            avg_latency = run_stats['total_latency_ms'] / run_stats['total_queries'] if run_stats['total_queries'] > 0 else 0
            throughput = (total_bytes / run_stats['total_time_seconds']) if run_stats['total_time_seconds'] > 0 else 0
            cache_hit_percentage = (run_stats['cache_hits'] / run_stats['total_queries'] * 100) if run_stats['total_queries'] > 0 else 0
            
            run_stats['average_latency_ms'] = round(avg_latency, 3)
            run_stats['throughput_bytes_per_sec'] = round(throughput, 2)
            run_stats['cache_hit_percentage'] = round(cache_hit_percentage, 2)
            
            stats['runs'].append(run_stats)
            
            # Update global stats
            stats['total_queries'] += run_stats['total_queries']
            stats['successful_resolutions'] += run_stats['successful']
            stats['failed_resolutions'] += run_stats['failed']
            stats['cache_hits'] += run_stats['cache_hits']
            stats['total_latency_ms'] += run_stats['total_latency_ms']
            
            # Print run summary
            print(f"\n{'-'*90}")
            print(f"RUN {run_num} SUMMARY:")
            print(f"  Total Queries: {run_stats['total_queries']}")
            print(f"  Successful: {run_stats['successful']}")
            print(f"  Failed: {run_stats['failed']}")
            print(f"  Cache Hits: {run_stats['cache_hits']}")
            print(f"  Average Latency: {avg_latency:.3f} ms")
            print(f"  Throughput: {throughput:.2f} bytes/sec")
            print(f"  Cache Hit %: {cache_hit_percentage:.2f}%")
            print(f"  Total Time: {run_stats['total_time_seconds']:.3f} seconds")
            print(f"{'-'*90}")
        
        # Calculate overall statistics
        stats['cache_misses'] = stats['total_queries'] - stats['cache_hits']
        stats['average_latency_ms'] = round(stats['total_latency_ms'] / stats['total_queries'], 3) if stats['total_queries'] > 0 else 0
        stats['cache_hit_percentage'] = round((stats['cache_hits'] / stats['total_queries'] * 100), 2) if stats['total_queries'] > 0 else 0
        
        # Print overall summary
        print(f"\n{'='*90}")
        print(f"OVERALL CACHE PERFORMANCE SUMMARY")
        print(f"{'='*90}")
        print(f"  Total Queries Executed: {stats['total_queries']}")
        print(f"  Successful Resolutions: {stats['successful_resolutions']}")
        print(f"  Failed Resolutions: {stats['failed_resolutions']}")
        print(f"  Cache Hits: {stats['cache_hits']}")
        print(f"  Cache Misses: {stats['cache_misses']}")
        print(f"  Cache Hit Percentage: {stats['cache_hit_percentage']:.2f}%")
        print(f"  Average Lookup Latency: {stats['average_latency_ms']:.3f} ms")
        
        if runs == 2:
            print(f"\n  Performance Improvement (Run 2 vs Run 1):")
            if len(stats['runs']) >= 2:
                latency_improvement = stats['runs'][0]['average_latency_ms'] - stats['runs'][1]['average_latency_ms']
                improvement_pct = (latency_improvement / stats['runs'][0]['average_latency_ms'] * 100) if stats['runs'][0]['average_latency_ms'] > 0 else 0
                print(f"    Latency Reduction: {latency_improvement:.3f} ms ({improvement_pct:.1f}% faster)")
                print(f"    Run 1 Cache Hits: {stats['runs'][0]['cache_hits']} ({stats['runs'][0]['cache_hit_percentage']:.2f}%)")
                print(f"    Run 2 Cache Hits: {stats['runs'][1]['cache_hits']} ({stats['runs'][1]['cache_hit_percentage']:.2f}%)")
        
        print(f"{'='*90}\n")
        
        # Save results to JSON
        output_file = pcap_file.replace('.pcap', '_cache_stats.json')
        with open(output_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        print(f"Results saved to: {output_file}\n")
        
        return stats

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python dns_cache_analyzer.py <pcap_file> [dns_server] [--single-run]")
        print("\nOptions:")
        print("  pcap_file    : Path to PCAP file with DNS queries")
        print("  dns_server   : DNS server IP (default: 10.0.0.5)")
        print("  --single-run : Run queries once only (default: run twice for cache testing)")
        print("\nExamples:")
        print("  python dns_cache_analyzer.py PCAPs_DNS_Resolver/PCAP_1_H1_f.pcap")
        print("  python dns_cache_analyzer.py PCAPs_DNS_Resolver/PCAP_1_H1_f.pcap 10.0.0.5")
        print("  python dns_cache_analyzer.py PCAPs_DNS_Resolver/PCAP_1_H1_f.pcap --single-run")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    dns_server = '10.0.0.5'
    run_twice = True
    
    # Parse arguments
    for arg in sys.argv[2:]:
        if arg == '--single-run':
            run_twice = False
        elif not arg.startswith('--'):
            dns_server = arg
    
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        sys.exit(1)
    
    # Create analyzer
    analyzer = DNSCacheAnalyzer(dns_server=dns_server)
    
    # Analyze PCAP
    analyzer.analyze_pcap(pcap_file, recursive_mode=True, run_twice=run_twice)

if __name__ == '__main__':
    main()
