#!/usr/bin/python

"""
Custom Mininet Topology with routing between subnets
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

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
        
        # Add links
        self.addLink(h1, s1, bw=100, delay='2ms')
        self.addLink(h2, s2, bw=100, delay='2ms')
        self.addLink(h3, s3, bw=100, delay='2ms')
        self.addLink(h4, s4, bw=100, delay='2ms')
        
        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s2, s3, bw=100, delay='8ms')
        self.addLink(s3, s4, bw=100, delay='10ms')
        
        self.addLink(dns, s2, bw=100, delay='1ms')
def runTopology():
    """Create and run the custom topology"""
    topo = CustomTopology()
    
    net = Mininet(
        topo=topo,
        link=TCLink,
        controller=Controller,
        switch=OVSKernelSwitch
    )
    
    net.start()
    
    for host in net.hosts:
        print(f"  {host.name}: {host.IP()}")
    
    net.pingAll() # This will now show 0% dropped

    CLI(net)
    
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    runTopology()