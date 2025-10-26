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
import tempfile
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
        

ANALYSIS_SCRIPT = '''#!/usr/bin/python
from scapy.all import rdpcap, DNSQR
import socket
import time
import statistics
import sys
import json

def extract_domains(pcap_file): 
    try:
        packets = rdpcap(pcap_file)
        domains = []
        total_bytes = 0

        for pkt in packets:
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode(errors='ignore')
                domains.append(qname.strip('.'))

            if pkt.haslayer('DNS'):
                total_bytes += len(pkt)

        return domains, total_bytes

    except Exception as e:
        print(f"Error reading pcap: {e}", file=sys.stderr)
        return [], 0

def analyze_dns(domains, total_bytes):
    latencies = []
    successes = 0
    failures = 0
    start_time = time.time()
    
    for domain in domains:
        t0 = time.time()
        try:
            socket.gethostbyname(domain)
            latencies.append(time.time() - t0)
            successes += 1
        except Exception:
            failures += 1
    
    total_time = time.time() - start_time
    avg_latency = statistics.mean(latencies) if latencies else 0
    throughput = total_bytes / total_time if total_time > 0 else 0
    
    return {
        "avg_latency": round(avg_latency, 4),
        "avg_throughput": round(throughput, 4),
        "success": successes,
        "failure": failures
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: script.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    domains, total_bytes = extract_domains(pcap_file)
    metrics = analyze_dns(domains, total_bytes)
    print(json.dumps(metrics))
'''

def run_dns_analysis_on_hosts(net):
    """Run DNS analysis on each host within Mininet"""
    base_dir = "PCAPs_DNS_Resolver"
    
    # Create temp script file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(ANALYSIS_SCRIPT)
        script_path = f.name
    
    # Make script executable
    os.chmod(script_path, 0o755)
    
    # Host to PCAP mapping
    host_pcap_map = {
        'h1': 'PCAP_1_H1_f.pcap',
        'h2': 'PCAP_2_H2_f.pcap',
        'h3': 'PCAP_3_H3_f.pcap',
        'h4': 'PCAP_4_H4_f.pcap'
    }
    
    print("\n===== DNS Resolution Metrics (from Mininet hosts) =====")
    
    for host_name, pcap_file in host_pcap_map.items():
        host = net.get(host_name)
        pcap_path = os.path.join(base_dir, pcap_file)
        
        # Check if PCAP exists on main host
        if not os.path.exists(pcap_path):
            print(f"\n[{host_name}] PCAP not found: {pcap_path}")
            continue
        
        print(f"\n[{host_name}] Analyzing {pcap_file}...")
        
        # Run analysis script on the Mininet host
        result = host.cmd(f'python {script_path} {pcap_path}')
        
        try:
            import json
            metrics = json.loads(result)
            print(f"  IP Address: {host.IP()}")
            print(f"  Average Latency: {metrics['avg_latency']} s")
            print(f"  Average Throughput: {metrics['avg_throughput']} bytes/s")
            print(f"  Successful Queries: {metrics['success']}")
            print(f"  Failed Queries: {metrics['failure']}")
        except Exception as e:
            print(f"  Error parsing results: {e}")
            print(f"  Raw output: {result}")
    
    # Cleanup temp script
    try:
        os.unlink(script_path)
    except:
        pass

def runTopology():
    topo = CustomTopology()
    net = Mininet(topo=topo, link=TCLink, controller=Controller)
    net.addNAT(link='dns', ip = "10.0.0.254/24").configDefault()
    net.start()
    print("\n*** Host IPs ***")
    for host in net.hosts:
        print(f"  {host.name}: {host.IP()}")
    # Give internet access to hosts (assuming your VM is online)
    for h in net.hosts:
        h.cmd("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")

    print("\n*** Testing connectivity")
    net.pingAll()
    
    # Run DNS metrics analysis
    print("\n*** Running DNS resolution analysis")
    run_dns_analysis_on_hosts(net)
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    runTopology()