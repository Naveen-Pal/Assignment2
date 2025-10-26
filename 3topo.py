#!/usr/bin/python
"""
Simple Mininet Topology with DNS Server
Author: Naveen-Pal
Date: 2025-10-25
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import time
import os

class CustomTopology(Topo):
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
        
        # Add links
        self.addLink(h1, s1, bw=100, delay='2ms')
        self.addLink(h2, s2, bw=100, delay='2ms')
        self.addLink(h3, s3, bw=100, delay='2ms')
        self.addLink(h4, s4, bw=100, delay='2ms')
        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s2, s3, bw=100, delay='8ms')
        self.addLink(s3, s4, bw=100, delay='10ms')
        self.addLink(dns, s2, bw=100, delay='1ms')

def setupDNS(net):
    """Setup DNS server on dns host"""
    print("\n*** Setting up DNS Server")
    
    dns = net.get('dns')

    dns.cmd('python dns_server.py &')
    
    # Wait for server to start
    time.sleep(2)
    
    # Check if running
    pid = dns.cmd('pgrep -f dns_server.py').strip()
    if pid:
        print(f"  ✓ DNS server running (PID: {pid})")
        return True
    else:
        print("  ✗ Failed to start DNS server")
        print("  Check log: dns cat /tmp/dns.log")
        return False
def runTests(net):
    """Run simple DNS tests"""
    print("\n*** Running DNS Tests")
    
    h1 = net.get('h1')
    
    print("\n[Test 1] Local record - h2.local")
    result = h1.cmd('nslookup h2.local 10.0.0.5 2>&1 | grep "Address:"')
    print(f"  {result.strip()}")
    
    print("\n[Test 2] External domain - google.com")
    result = h1.cmd('nslookup google.com 10.0.0.5 2>&1 | grep "Address:"')
    print(f"  {result.strip()}")
    
    print("\n[Test 3] Cache test - google.com again")
    result = h1.cmd('nslookup google.com 10.0.0.5 2>&1 | grep "Address:"')
    print(f"  {result.strip()}")

def main():
    topo = CustomTopology()
    net = Mininet(topo=topo, link=TCLink, controller=Controller)
    net.addNAT(link='dns', ip = "10.0.0.254/24").configDefault()
    net.start()
    
    print("\n*** Network Started")
    print("Hosts:")
    for host in net.hosts:
        print(f"  {host.name}: {host.IP()}")
    
    # Setup DNS server
    if not setupDNS(net):
        print("\nFailed to setup DNS. Stopping...")
        net.stop()
        return
    # for host in net.hosts:
    #     if host.name == 'dns' or host.name == 'nat0':
    #         continue
        
    #     host.cmd('bash -c "echo nameserver 10.0.0.5 > /etc/resolv.conf"')

    #     print("host:", host)
    
    # Test connectivity
    print("\n*** Testing connectivity")
    net.pingAll()
    
    # # Run DNS tests
    # runTests(net)

    # Start CLI
    CLI(net)
    
    # Cleanup
    print("\n*** Stopping DNS server")
    dns = net.get('dns')
    dns.cmd('pkill -f dns_server.py')
    
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()