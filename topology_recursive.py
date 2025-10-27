#!/usr/bin/python

"""
Custom Mininet Topology for Recursive DNS Resolution Testing
Tests recursive DNS resolution mode with modified PCAP files
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import time
import os

class RecursiveDNSTopology(Topo):
    """Custom topology for testing recursive DNS resolution"""
    
    def build(self):
        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        
        dns = self.addHost('dns', ip='10.0.0.5/24')
        
        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        
        # Add links with bandwidth and delay parameters
        self.addLink(h1, s1, bw=100, delay='2ms')
        self.addLink(h2, s2, bw=100, delay='2ms')
        self.addLink(h3, s3, bw=100, delay='2ms')
        self.addLink(h4, s4, bw=100, delay='2ms')
        
        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s2, s3, bw=100, delay='8ms')
        self.addLink(s3, s4, bw=100, delay='10ms')
        
        self.addLink(dns, s2, bw=100, delay='1ms')

def modify_pcap_files():
    """Modify PCAP files to set recursive_mode flag"""
    print("\n" + "="*80)
    print("STEP 1: MODIFYING PCAP FILES TO SET RECURSIVE MODE FLAG")
    print("="*80)
    
    pcap_dir = "PCAPs_DNS_Resolver"
    if not os.path.exists(pcap_dir):
        print(f"Error: {pcap_dir} directory not found")
        return False
    
    # Modify all PCAP files in the directory
    os.system(f"python3 modify_pcap_recursive.py --dir {pcap_dir}")
    
    print("\nPCAP files modified successfully!\n")
    return True

def run_dns_clients(net):
    """Run DNS clients on all hosts with recursive mode enabled"""
    print("\n" + "="*80)
    print("STEP 3: RUNNING DNS CLIENTS WITH RECURSIVE MODE")
    print("="*80 + "\n")
    
    results_summary = []
    
    for i in range(1, 5):
        host = net.get(f'h{i}')
        # Use the modified PCAP files with recursive flag set
        pcap_file = f'PCAPs_DNS_Resolver/PCAP_{i}_H{i}_f_recursive.pcap'
        
        # Check if modified PCAP exists, otherwise use original
        if not os.path.exists(pcap_file):
            print(f"Warning: {pcap_file} not found, using original")
            pcap_file = f'PCAPs_DNS_Resolver/PCAP_{i}_H{i}_f.pcap'
        
        print(f"\n{'='*80}")
        print(f"HOST {i} (h{i}) - Processing {pcap_file}")
        print(f"{'='*80}")
        
        # Run DNS client with recursive mode
        result = host.cmd(f'python3 dns_client_recursive.py {pcap_file} 10.0.0.5')
        print(result)
        
        results_summary.append(f"Host h{i}: {pcap_file}")
        time.sleep(1)
    
    return results_summary

def print_final_summary():
    """Print final summary of all results"""
    print("\n" + "="*80)
    print("FINAL SUMMARY - RECURSIVE DNS RESOLUTION TEST")
    print("="*80)
    
    # Check for generated statistics files
    import json
    import glob
    
    stats_files = glob.glob("PCAPs_DNS_Resolver/*_recursive_stats.json")
    
    if not stats_files:
        print("No statistics files found")
        return
    
    print(f"\nFound {len(stats_files)} statistics files:\n")
    
    total_queries = 0
    total_successful = 0
    total_failed = 0
    total_cache_hits = 0
    total_latency = 0
    file_count = 0
    
    print(f"{'Host':<8} {'Queries':<10} {'Success':<10} {'Failed':<10} {'Cache Hits':<12} {'Avg Latency':<15} {'Throughput':<20}")
    print("="*100)
    
    for stats_file in sorted(stats_files):
        try:
            with open(stats_file, 'r') as f:
                stats = json.load(f)
            
            host_name = stats['pcap_file'].replace('_f_recursive_stats.json', '')
            queries = stats['total_queries']
            successful = stats['successful_resolutions']
            failed = stats['failed_resolutions']
            cache_hits = stats['cache_hits']
            avg_latency = stats['average_lookup_latency_ms']
            throughput = stats['average_throughput_bytes_per_sec']
            
            print(f"{host_name:<8} {queries:<10} {successful:<10} {failed:<10} {cache_hits:<12} {avg_latency:<15.2f} {throughput:<20.2f}")
            
            total_queries += queries
            total_successful += successful
            total_failed += failed
            total_cache_hits += cache_hits
            total_latency += avg_latency
            file_count += 1
            
        except Exception as e:
            print(f"Error reading {stats_file}: {e}")
    
    print("="*100)
    
    if file_count > 0:
        avg_overall_latency = total_latency / file_count
        cache_hit_percentage = (total_cache_hits / total_queries * 100) if total_queries > 0 else 0
        success_percentage = (total_successful / total_queries * 100) if total_queries > 0 else 0
        
        print(f"\nOVERALL STATISTICS:")
        print(f"  Total Queries:                {total_queries}")
        print(f"  Successfully Resolved:        {total_successful} ({success_percentage:.1f}%)")
        print(f"  Failed Resolutions:           {total_failed}")
        print(f"  Total Cache Hits:             {total_cache_hits} ({cache_hit_percentage:.1f}%)")
        print(f"  Average Lookup Latency:       {avg_overall_latency:.2f} ms")
    
    print("\n" + "="*80)
    
    # Check server logs
    if os.path.exists('dns_query_logs_recursive.json'):
        print("\nServer query logs saved to: dns_query_logs_recursive.json")
    
    if os.path.exists('dns_server_stats_recursive.json'):
        print("Server statistics saved to: dns_server_stats_recursive.json")
        
        try:
            with open('dns_server_stats_recursive.json', 'r') as f:
                server_stats = json.load(f)
            
            print("\nSERVER-SIDE STATISTICS:")
            print(f"  Total Queries Received:       {server_stats['server_stats']['total_queries']}")
            print(f"  Recursive Queries:            {server_stats['server_stats']['recursive_queries']}")
            print(f"  Iterative Queries:            {server_stats['server_stats']['iterative_queries']}")
            print(f"  Cache Hit Rate:               {server_stats['cache_hit_percentage']:.2f}%")
            print(f"  Average Latency (server):     {server_stats['average_lookup_latency_ms']:.2f} ms")
        except:
            pass
    
    print("="*80 + "\n")

def runTopology():
    """Create and run the custom topology with recursive DNS testing"""
    
    # Step 1: Modify PCAP files
    if not modify_pcap_files():
        print("Failed to modify PCAP files. Exiting.")
        return
    
    # Step 2: Create and start network
    print("\n" + "="*80)
    print("STEP 2: STARTING MININET TOPOLOGY")
    print("="*80 + "\n")
    
    topo = RecursiveDNSTopology()
    net = Mininet(
        topo=topo,
        link=TCLink,
        controller=Controller,
        switch=OVSKernelSwitch
    )
    
    # Add NAT for external DNS access
    net.addNAT(link='dns', ip="10.0.0.254/24").configDefault()
    net.start()
    
    print("\nNetwork Hosts:")
    for host in net.hosts:
        print(f"  {host.name}: {host.IP()}")
    
    # Configure DNS resolver on hosts
    print("\nConfiguring DNS resolver on hosts...")
    for host in net.hosts:
        if host.name == 'dns':
            continue
        host.cmd(f'echo "nameserver 10.0.0.5" > /etc/resolv.conf')
    
    # Start DNS server with recursive support
    dns = net.get('dns')
    print("\nStarting DNS server with RECURSIVE SUPPORT...")
    dns.cmd('python3 dns_server_recursive.py > /tmp/dns_recursive.log 2>&1 &')
    time.sleep(3)
    
    # Check if DNS server is running
    pid = dns.cmd('pgrep -f dns_server_recursive.py').strip()
    if pid:
        print(f"  DNS server running (PID: {pid})")
    else:
        print("  Failed to start DNS server")
        print("  Check log: cat /tmp/dns_recursive.log")
        net.stop()
        return
    
    # Test connectivity
    print("\n" + "="*80)
    print("TESTING NETWORK CONNECTIVITY")
    print("="*80)
    net.pingAll()
    
    # Run DNS clients
    results = run_dns_clients(net)
    
    # Wait a bit for all queries to complete
    print("\nWaiting for all queries to complete...")
    time.sleep(5)
    
    # Print final summary
    print_final_summary()
    
    # Open CLI for manual testing if needed
    print("\n" + "="*80)
    print("Opening Mininet CLI for manual testing...")
    print("Commands you can try:")
    print("  h1 python3 dns_client_recursive.py PCAPs_DNS_Resolver/PCAP_1_H1_f_recursive.pcap")
    print("  dns cat /tmp/dns_recursive.log")
    print("  xterm dns h1")
    print("="*80 + "\n")
    
    CLI(net)
    
    # Cleanup
    print("\nShutting down DNS server...")
    dns.cmd('pkill -f dns_server_recursive.py')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    runTopology()
