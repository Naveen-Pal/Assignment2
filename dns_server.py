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
    def __init__(self, max_size=1000):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.lock = threading.Lock()
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if time.time() < expiry:
                    self.cache.move_to_end(key)
                    return value
                else:
                    del self.cache[key]
            return None
    
    def set(self, key, value, ttl=300):
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
            
            expiry = time.time() + ttl
            self.cache[key] = (value, expiry)

class DNSServer:
    """DNS Server with local records, caching, and external DNS forwarding"""
    
    TYPE_A = 1
    TYPE_AAAA = 28
    
    def __init__(self, port=5353, external_dns=['8.8.8.8', '1.1.1.1'], records_file='dns_records.json'):
        self.port = port
        self.external_dns = external_dns
        self.cache = DNSCache()
        self.local_records = self.load_records(records_file)
        self.socket = None
        self.query_logs = []
        
    def load_records(self, filename):
        """Load local DNS records from JSON file"""
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
        else:
            default_records = {
                'example.local': {'A': '192.168.1.100'},
                'test.local': {'A': '10.0.0.50'}
            }
            with open(filename, 'w') as f:
                json.dump(default_records, f, indent=2)
            return default_records
    
    def log(self, message):
        """Log with timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}")
    
    def save_log(self, log_entry):
        """Save query log to JSON file"""
        self.query_logs.append(log_entry)
        with open('dns_query_logs.json', 'w') as f:
            json.dump(self.query_logs, f, indent=2)
    
    def parse_dns_query(self, data):
        """Parse DNS query packet"""
        try:
            transaction_id = struct.unpack('!H', data[0:2])[0]
            
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
        flags = 0x8180
        
        response = struct.pack('!HHHHHH', transaction_id, flags, 1, 1, 0, 0)
        
        # Question section
        for part in domain.split('.'):
            response += bytes([len(part)]) + part.encode('utf-8')
        response += b'\x00'
        response += struct.pack('!HH', query['qtype'], query['qclass'])
        
        # Answer section
        response += b'\xc0\x0c'
        response += struct.pack('!HH', query['qtype'], query['qclass'])
        response += struct.pack('!I', 300)
        
        ip_parts = [int(x) for x in ip_address.split('.')]
        response += struct.pack('!H', 4)
        response += bytes(ip_parts)
        
        return response
    
    def check_local_records(self, domain, qtype):
        """Check local DNS records"""
        if domain in self.local_records:
            record_type = 'A' if qtype == self.TYPE_A else 'AAAA'
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
        """Handle incoming DNS query with detailed logging"""
        start_time = time.time()
        query = self.parse_dns_query(data)
        if not query:
            return
        
        domain = query['domain']
        qtype = query['qtype']
        qtype_name = 'A' if qtype == self.TYPE_A else f'TYPE_{qtype}'
        
        # Initialize log entry
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'domain': domain,
            'query_type': qtype_name,
            'client_ip': addr[0]
        }
        
        self.log(f"Query from {addr}: {domain} ({qtype_name})")
        
        # Step 1: Check local records
        local_start = time.time()
        local_result = self.check_local_records(domain, qtype)
        if local_result:
            rtt = (time.time() - local_start) * 1000
            log_entry.update({
                'resolution_mode': 'Local Records',
                'dns_server_contacted': 'localhost',
                'step': 'Local',
                'response': local_result,
                'rtt_ms': round(rtt, 2),
                'total_time_ms': round((time.time() - start_time) * 1000, 2),
                'cache_status': 'N/A'
            })
            self.log(f"Found in local records: {domain} -> {local_result}")
            self.save_log(log_entry)
            response = self.build_dns_response(query, local_result)
            self.socket.sendto(response, addr)
            return
        
        # Step 2: Check cache
        cache_start = time.time()
        cached_response = self.check_cache(domain, qtype)
        if cached_response:
            rtt = (time.time() - cache_start) * 1000
            log_entry.update({
                'resolution_mode': 'Cache',
                'dns_server_contacted': 'cache',
                'step': 'Cache',
                'response': 'Cached response',
                'rtt_ms': round(rtt, 2),
                'total_time_ms': round((time.time() - start_time) * 1000, 2),
                'cache_status': 'HIT'
            })
            self.log(f"Found in cache: {domain}")
            self.save_log(log_entry)
            self.socket.sendto(cached_response, addr)
            return
        
        # Step 3: Query external DNS servers
        log_entry['cache_status'] = 'MISS'
        for dns_server in self.external_dns:
            self.log(f"Forwarding to external DNS: {dns_server}")
            ext_start = time.time()
            response = self.query_external_dns(data, dns_server)
            rtt = (time.time() - ext_start) * 1000
            
            if response:
                log_entry.update({
                    'resolution_mode': 'External DNS',
                    'dns_server_contacted': dns_server,
                    'step': 'Authoritative',
                    'response': 'Resolved',
                    'rtt_ms': round(rtt, 2),
                    'total_time_ms': round((time.time() - start_time) * 1000, 2)
                })
                self.log(f"Resolved via {dns_server}: {domain}")
                self.save_log(log_entry)
                
                # Cache the response
                cache_key = f"{domain}:{qtype}"
                self.cache.set(cache_key, response, ttl=300)
                
                self.socket.sendto(response, addr)
                return
        
        # Failed to resolve
        log_entry.update({
            'resolution_mode': 'Failed',
            'dns_server_contacted': 'None',
            'step': 'Failed',
            'response': 'No response',
            'rtt_ms': 0,
            'total_time_ms': round((time.time() - start_time) * 1000, 2)
        })
        self.log(f"Failed to resolve: {domain}")
        self.save_log(log_entry)
    
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