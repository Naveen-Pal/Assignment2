#!/usr/bin/env python3
"""
DNS Server Implementation
Checks local records -> cache -> external DNS servers
"""

import socket
import struct
import threading
import time
from collections import OrderedDict
from datetime import datetime
import argparse
import json
import os

class DNSCache:
    """LRU Cache with TTL support for DNS responses"""
    def __init__(self, max_size=1000):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.lock = threading.Lock()
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if time.time() < expiry:
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    return value
                else:
                    # Expired, remove from cache
                    del self.cache[key]
            return None
    
    def set(self, key, value, ttl=300):
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.max_size:
                # Remove oldest item
                self.cache.popitem(last=False)
            
            expiry = time.time() + ttl
            self.cache[key] = (value, expiry)

class DNSServer:
    """DNS Server with local records, caching, and external DNS forwarding"""
    
    # DNS Record Types
    TYPE_A = 1
    TYPE_AAAA = 28
    TYPE_CNAME = 5
    TYPE_MX = 15
    TYPE_NS = 2
    TYPE_TXT = 16
    
    def __init__(self, port=5353, external_dns=['8.8.8.8', '1.1.1.1'], records_file='dns_records.json'):
        self.port = port
        self.external_dns = external_dns
        self.cache = DNSCache()
        self.local_records = self.load_records(records_file)
        self.socket = None
        
    def load_records(self, filename):
        """Load local DNS records from JSON file"""
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
        else:
            # Default records
            default_records = {
                'example.local': {'A': '192.168.1.100'},
                'test.local': {'A': '10.0.0.50'},
                'mail.local': {'A': '192.168.1.200', 'MX': '10 mail.local'}
            }
            with open(filename, 'w') as f:
                json.dump(default_records, f, indent=2)
            return default_records
    
    def log(self, message):
        """Log with timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}")
    
    def parse_dns_query(self, data):
        """Parse DNS query packet"""
        try:
            # DNS Header (12 bytes)
            transaction_id = struct.unpack('!H', data[0:2])[0]
            flags = struct.unpack('!H', data[2:4])[0]
            questions = struct.unpack('!H', data[4:6])[0]
            
            # Parse question section
            offset = 12
            domain_parts = []
            while True:
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                domain_parts.append(data[offset+1:offset+1+length].decode('utf-8'))
                offset += length + 1
            
            domain = '.'.join(domain_parts)
            qtype = struct.unpack('!H', data[offset:offset+2])[0]
            qclass = struct.unpack('!H', data[offset+2:offset+4])[0]
            
            return {
                'transaction_id': transaction_id,
                'domain': domain,
                'qtype': qtype,
                'qclass': qclass,
                'raw_query': data
            }
        except Exception as e:
            self.log(f"Error parsing DNS query: {e}")
            return None
    
    def build_dns_response(self, query, ip_address):
        """Build DNS response packet"""
        transaction_id = query['transaction_id']
        domain = query['domain']
        
        # DNS Header
        # Flags: QR=1 (response), AA=1, RD=1, RA=1
        flags = 0x8180
        response = struct.pack('!HHHHHH', 
            transaction_id,  # Transaction ID
            flags,           # Flags
            1,               # Questions
            1,               # Answer RRs
            0,               # Authority RRs
            0                # Additional RRs
        )
        
        # Question section (copy from original query)
        domain_parts = domain.split('.')
        for part in domain_parts:
            response += bytes([len(part)]) + part.encode('utf-8')
        response += b'\x00'  # End of domain
        response += struct.pack('!HH', query['qtype'], query['qclass'])
        
        # Answer section
        # Name pointer to question
        response += b'\xc0\x0c'
        
        # Type A (1), Class IN (1)
        response += struct.pack('!HH', query['qtype'], query['qclass'])
        
        # TTL (300 seconds)
        response += struct.pack('!I', 300)
        
        # Data length and IP address
        ip_parts = [int(x) for x in ip_address.split('.')]
        response += struct.pack('!H', 4)  # Data length
        response += bytes(ip_parts)
        
        return response
    
    def check_local_records(self, domain, qtype):
        """Check local DNS records"""
        if domain in self.local_records:
            record_type = 'A' if qtype == self.TYPE_A else 'AAAA' if qtype == self.TYPE_AAAA else 'CNAME'
            if record_type in self.local_records[domain]:
                return self.local_records[domain][record_type]
        return None
    
    def check_cache(self, domain, qtype):
        """Check DNS cache"""
        cache_key = f"{domain}:{qtype}"
        return self.cache.get(cache_key)
    
    def query_external_dns(self, query_data, dns_server='8.8.8.8'):
        """Forward query to external DNS server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(query_data, (dns_server, 53))
            response, _ = sock.recvfrom(512)
            sock.close()
            return response
        except Exception as e:
            self.log(f"Error querying external DNS {dns_server}: {e}")
            return None
    
    def handle_query(self, data, addr):
        """Handle incoming DNS query"""
        query = self.parse_dns_query(data)
        if not query:
            return
        
        domain = query['domain']
        qtype = query['qtype']
        qtype_name = 'A' if qtype == self.TYPE_A else f'TYPE_{qtype}'
        
        self.log(f"Query from {addr}: {domain} ({qtype_name})")
        
        # Step 1: Check local records
        local_result = self.check_local_records(domain, qtype)
        if local_result:
            self.log(f"Found in local records: {domain} -> {local_result}")
            response = self.build_dns_response(query, local_result)
            self.socket.sendto(response, addr)
            return
        
        # Step 2: Check cache
        cached_response = self.check_cache(domain, qtype)
        if cached_response:
            self.log(f"Found in cache: {domain}")
            self.socket.sendto(cached_response, addr)
            return
        
        # Step 3: Query external DNS servers
        for dns_server in self.external_dns:
            self.log(f"Forwarding to external DNS: {dns_server}")
            response = self.query_external_dns(data, dns_server)
            if response:
                # Cache the response
                cache_key = f"{domain}:{qtype}"
                self.cache.set(cache_key, response, ttl=300)
                self.log(f"Resolved via {dns_server}: {domain}")
                self.socket.sendto(response, addr)
                return
        
        self.log(f"Failed to resolve: {domain}")
    
    def start(self):
        """Start DNS server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', self.port))
        
        self.log(f"DNS Server started on port {self.port}")
        self.log(f"External DNS servers: {', '.join(self.external_dns)}")
        self.log(f"Loaded {len(self.local_records)} local records")
        
        try:
            while True:
                data, addr = self.socket.recvfrom(512)
                # Handle each query in a separate thread
                thread = threading.Thread(target=self.handle_query, args=(data, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            self.log("Server shutting down...")
        finally:
            self.socket.close()

def main():
    parser = argparse.ArgumentParser(description='DNS Server')
    parser.add_argument('-p', '--port', type=int, default=5353, help='Port to listen on (default: 5353)')
    parser.add_argument('-d', '--dns', nargs='+', default=['8.8.8.8', '1.1.1.1'], 
                        help='External DNS servers (default: 8.8.8.8 1.1.1.1)')
    parser.add_argument('-r', '--records', default='dns_records.json',
                        help='DNS records file (default: dns_records.json)')
    
    args = parser.parse_args()
    
    server = DNSServer(port=args.port, external_dns=args.dns, records_file=args.records)
    server.start()

if __name__ == '__main__':
    main()