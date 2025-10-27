#!/usr/bin/python

"""
Custom Mininet Topology for Testing DNS Cache Performance
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import time
import subprocess

class CustomTopology(Topo):
    """Custom topology with bandwidth and delay parameters"""
    
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
        
        # Add links with bandwidth and delay
        self.addLink(h1, s1, bw=100, delay='2ms')
        self.addLink(h2, s2, bw=100, delay='2ms')
        self.addLink(h3, s3, bw=100, delay='2ms')
        self.addLink(h4, s4, bw=100, delay='2ms')
        
        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s2, s3, bw=100, delay='8ms')
        self.addLink(s3, s4, bw=100, delay='10ms')
        
        self.addLink(dns, s2, bw=100, delay='1ms')

def runTopology():
    """Create and run the custom topology for cache testing"""
    topo = CustomTopology()
    net = Mininet(
        topo=topo,
        link=TCLink,
        controller=Controller,
        switch=OVSKernelSwitch
    )
    
    net.addNAT(link='dns', ip="10.0.0.254/24").configDefault()
    net.start()
    
    print("\n" + "="*80)
    print("DNS CACHE TESTING TOPOLOGY")
    print("="*80)
    print("\nHost IP Addresses:")
    for host in net.hosts:
        print(f"  {host.name}: {host.IP()}")
    
    # Configure resolv.conf for all hosts
    for host in net.hosts:
        if host.name == 'dns':
            continue
        host.cmd(f'echo "nameserver 10.0.0.5" > /etc/resolv.conf')
    
    # Start DNS server with recursive support
    dns = net.get('dns')
    print("\n" + "="*80)
    print("Starting DNS Server with Caching and Recursive Resolution...")
    print("="*80)
    
    dns.cmd('python3 dns_server_recursive.py --supports-recursion > /tmp/dns_server.log 2>&1 &')
    time.sleep(3)
    
    pid = dns.cmd('pgrep -f dns_server_recursive.py').strip()
    if pid:
        print(f"  ✓ DNS server running (PID: {pid})")
        print(f"  Server supports: Recursive Resolution + Caching")
        print(f"  Server listening on: 10.0.0.5:5353")
    else:
        print("  ✗ Failed to start DNS server")
        print("  Check log: cat /tmp/dns_server.log")
        dns.stop()
        net.stop()
        return
    
    print("\n" + "="*80)
    print("Testing Cache Performance")
    print("="*80)
    
    # Run cache analyzer on each host
    pcap_files = [
        'PCAPs_DNS_Resolver/PCAP_1_H1_f.pcap',
        'PCAPs_DNS_Resolver/PCAP_2_H2_f.pcap',
        'PCAPs_DNS_Resolver/PCAP_3_H3_f.pcap',
        'PCAPs_DNS_Resolver/PCAP_4_H4_f.pcap'
    ]
    
    print("\nRunning cache analysis on all PCAP files...")
    print("This will execute queries twice to measure cache performance.\n")
    
    for i, pcap_file in enumerate(pcap_files, 1):
        h = net.get(f'h{i}')
        print(f"\n{'='*80}")
        print(f"Host h{i} - Processing {pcap_file}")
        print(f"{'='*80}")
        
        result = h.cmd(f'python3 dns_cache_analyzer.py {pcap_file}')
        print(result)
    
    print("\n" + "="*80)
    print("Cache Testing Complete")
    print("="*80)
    print("\nYou can now:")
    print("  1. Check individual cache statistics: cat PCAPs_DNS_Resolver/PCAP_*_cache_stats.json")
    print("  2. View DNS server logs: cat dns_query_logs_recursive.json")
    print("  3. Run manual queries from any host")
    print("  4. Type 'exit' to stop the topology")
    print("\nEntering Mininet CLI...\n")
    
    CLI(net)
    
    # Cleanup
    print("\nStopping DNS server...")
    dns.cmd('pkill -f dns_server_recursive.py')
    net.stop()

def main():
    """Main entry point"""
    print("\n" + "="*80)
    print("DNS CACHE PERFORMANCE TESTING ENVIRONMENT")
    print("="*80)
    print("\nThis topology will:")
    print("  1. Start a DNS server with caching and recursive resolution")
    print("  2. Run DNS queries from PCAP files")
    print("  3. Execute queries twice to measure cache hit rate")
    print("  4. Record metrics: latency, throughput, cache %, success/failure rates")
    print("\n" + "="*80 + "\n")
    
    setLogLevel('info')
    runTopology()

if __name__ == '__main__':
    main()
