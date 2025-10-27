#!/usr/bin/env python3
"""
Run cache analysis on all PCAP files
Executes dns_cache_analyzer.py on all PCAP files and generates a summary report
"""

import os
import sys
import json
import subprocess
from datetime import datetime

def run_cache_analysis():
    """Run cache analysis on all PCAP files"""
    
    pcap_dir = "PCAPs_DNS_Resolver"
    pcap_files = [
        f"{pcap_dir}/PCAP_1_H1_f.pcap",
        f"{pcap_dir}/PCAP_2_H2_f.pcap",
        f"{pcap_dir}/PCAP_3_H3_f.pcap",
        f"{pcap_dir}/PCAP_4_H4_f.pcap"
    ]
    
    print("="*100)
    print("DNS CACHE ANALYSIS - BATCH PROCESSOR")
    print("="*100)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Number of PCAP files: {len(pcap_files)}")
    print("="*100)
    
    all_results = []
    
    for i, pcap_file in enumerate(pcap_files, 1):
        print(f"\n\n{'#'*100}")
        print(f"# PROCESSING FILE {i}/{len(pcap_files)}: {pcap_file}")
        print(f"{'#'*100}\n")
        
        if not os.path.exists(pcap_file):
            print(f"WARNING: File not found: {pcap_file}")
            continue
        
        # Run dns_cache_analyzer.py
        try:
            result = subprocess.run(
                ['python3', 'dns_cache_analyzer.py', pcap_file],
                capture_output=False,
                text=True
            )
            
            # Load the generated stats file
            stats_file = pcap_file.replace('.pcap', '_cache_stats.json')
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    stats = json.load(f)
                    all_results.append(stats)
            
        except Exception as e:
            print(f"ERROR processing {pcap_file}: {e}")
    
    # Generate summary report
    print("\n\n")
    print("="*100)
    print("CACHE PERFORMANCE SUMMARY - ALL PCAP FILES")
    print("="*100)
    
    if len(all_results) == 0:
        print("No results to summarize")
        return
    
    print(f"\n{'File':<30} {'Queries':<10} {'Success':<10} {'Failed':<10} {'Cache %':<12} {'Avg Latency':<15}")
    print("-"*100)
    
    total_queries = 0
    total_successful = 0
    total_failed = 0
    total_cache_hits = 0
    total_latency = 0
    
    for result in all_results:
        pcap_name = os.path.basename(result['pcap_file'])
        queries = result['total_queries']
        successful = result['successful_resolutions']
        failed = result['failed_resolutions']
        cache_pct = result['cache_hit_percentage']
        avg_latency = result['average_latency_ms']
        
        print(f"{pcap_name:<30} {queries:<10} {successful:<10} {failed:<10} {cache_pct:<11.2f}% {avg_latency:<14.3f} ms")
        
        total_queries += queries
        total_successful += successful
        total_failed += failed
        total_cache_hits += result['cache_hits']
        total_latency += result['total_latency_ms']
    
    print("-"*100)
    
    overall_cache_pct = (total_cache_hits / total_queries * 100) if total_queries > 0 else 0
    overall_avg_latency = (total_latency / total_queries) if total_queries > 0 else 0
    
    print(f"{'TOTAL':<30} {total_queries:<10} {total_successful:<10} {total_failed:<10} {overall_cache_pct:<11.2f}% {overall_avg_latency:<14.3f} ms")
    
    print("\n" + "="*100)
    print("KEY METRICS:")
    print("="*100)
    print(f"  Total Queries Executed: {total_queries}")
    print(f"  Successfully Resolved: {total_successful}")
    print(f"  Failed Resolutions: {total_failed}")
    print(f"  Total Cache Hits: {total_cache_hits}")
    print(f"  Overall Cache Hit %: {overall_cache_pct:.2f}%")
    print(f"  Average Lookup Latency: {overall_avg_latency:.3f} ms")
    
    # Calculate throughput
    total_bytes = sum(r.get('total_bytes', 0) for r in all_results)
    if len(all_results) > 0 and all_results[0].get('runs'):
        total_time = sum(run['total_time_seconds'] for r in all_results for run in r['runs'])
        if total_time > 0:
            throughput = total_bytes / total_time
            print(f"  Average Throughput: {throughput:.2f} bytes/sec")
    
    print("="*100)
    
    # Save combined summary
    summary = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_queries': total_queries,
        'successful_resolutions': total_successful,
        'failed_resolutions': total_failed,
        'total_cache_hits': total_cache_hits,
        'cache_hit_percentage': round(overall_cache_pct, 2),
        'average_latency_ms': round(overall_avg_latency, 3),
        'pcap_results': all_results
    }
    
    with open('cache_analysis_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nSummary saved to: cache_analysis_summary.json\n")

if __name__ == '__main__':
    run_cache_analysis()
