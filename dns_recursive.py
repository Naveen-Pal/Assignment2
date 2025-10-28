#!/usr/bin/env python3
"""
DNS Server Implementation with Recursive Resolution Mode
Supports both recursive and iterative resolution modes
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
        self.hit_count = 0
        self.miss_count = 0
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if time.time() < expiry:
                    self.cache.move_to_end(key)
                    self.hit_count += 1
                    return value
                else:
                    del self.cache[key]
                    self.miss_count += 1
            else:
                self.miss_count += 1
            return None
    
    def set(self, key, value, ttl=300):
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
            
            expiry = time.time() + ttl
            self.cache[key] = (value, expiry)
    
    def get_stats(self):
        """Return cache statistics"""
        total = self.hit_count + self.miss_count
        hit_percentage = (self.hit_count / total * 100) if total > 0 else 0
        return {
            'hits': self.hit_count,
            'misses': self.miss_count,
            'total': total,
            'hit_percentage': round(hit_percentage, 2)
        }

class RecursiveDNSServer:
    """DNS Server with recursive and iterative resolution support"""
    
    TYPE_A = 1
    TYPE_AAAA = 28
    
    # DNS Header flags
    QR_MASK = 0x8000  # Query/Response
    RD_MASK = 0x0100  # Recursion Desired
    RA_MASK = 0x0080  # Recursion Available
    
    def __init__(self, port=5353, external_dns=['8.8.8.8', '1.1.1.1'], 
                 records_file='dns_records.json', supports_recursion=True):
        self.port = port
        self.external_dns = external_dns
        self.cache = DNSCache()
        self.local_records = self.load_records(records_file)
        self.socket = None
        self.query_logs = []
        self.supports_recursion = supports_recursion
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'successful_resolutions': 0,
            'failed_resolutions': 0,
            'recursive_queries': 0,
            'iterative_queries': 0,
            'local_resolutions': 0,
            'cache_resolutions': 0,
            'external_resolutions': 0,
            'total_latency_ms': 0
        }
        
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
        with open('dns_query_logs_recursive.json', 'w') as f:
            json.dump(self.query_logs, f, indent=2)
    
    def parse_dns_query(self, data):
        """Parse DNS query packet and extract recursion desired flag"""
        try:
            transaction_id = struct.unpack('!H', data[0:2])[0]
            flags = struct.unpack('!H', data[2:4])[0]
            
            # Check if recursion is desired (RD bit)
            recursion_desired = bool(flags & self.RD_MASK)
            
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
                'recursion_desired': recursion_desired,
                'raw_query': data
            }
        except Exception as e:
            self.log(f"Error parsing DNS query: {e}")
            return None
    
    def build_dns_response(self, query, ip_address, recursion_available=True):
        """Build DNS response packet with recursion available flag"""
        transaction_id = query['transaction_id']
        domain = query['domain']
        
        # Set flags: QR=1 (response), RD=query's RD, RA=recursion_available
        flags = 0x8000  # QR bit set (response)
        if query.get('recursion_desired', False):
            flags |= self.RD_MASK  # Echo back RD bit
        if recursion_available and self.supports_recursion:
            flags |= self.RA_MASK  # Set RA bit
        flags |= 0x0180  # Standard response, no error
        
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
    
    def query_external_dns_recursive(self, query_data, dns_server='8.8.8.8'):
        """Forward query to external DNS server with recursion"""
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
    
    def resolve_iteratively(self, domain, qtype):
        """
        Iterative resolution: Query multiple servers step by step
        Simulated iterative resolution for demonstration
        """
        # In a real implementation, this would query root servers, 
        # then TLD servers, then authoritative servers
        # For this assignment, we'll simulate by querying external DNS without RD flag
        self.log(f"Performing iterative resolution for {domain}")
        
        # Simulate step-by-step resolution
        steps = [
            ('Root Server', '198.41.0.4'),
            ('TLD Server', '192.5.6.30'),
            ('Authoritative', self.external_dns[0])
        ]
        
        for step_name, server in steps:
            self.log(f"  Step: {step_name} ({server})")
            # In simulation, we only query the final server
            if step_name == 'Authoritative':
                try:
                    # Build query without RD flag
                    query = struct.pack('!HHHHHH', 0x1234, 0x0000, 1, 0, 0, 0)
                    for part in domain.split('.'):
                        query += bytes([len(part)]) + part.encode('utf-8')
                    query += b'\x00'
                    query += struct.pack('!HH', qtype, 1)
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5)
                    sock.sendto(query, (server, 53))
                    response, _ = sock.recvfrom(512)
                    sock.close()
                    return response
                except:
                    pass
        
        return None
    
    def handle_query(self, data, addr):
        """Handle incoming DNS query with recursive/iterative mode support"""
        start_time = time.time()
        self.stats['total_queries'] += 1
        
        query = self.parse_dns_query(data)
        if not query:
            return
        
        domain = query['domain']
        qtype = query['qtype']
        qtype_name = 'A' if qtype == self.TYPE_A else f'TYPE_{qtype}'
        recursion_desired = query.get('recursion_desired', False)
        
        # Initialize log entry
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'domain': domain,
            'query_type': qtype_name,
            'client_ip': addr[0],
            'recursion_desired': recursion_desired,
            'recursion_available': self.supports_recursion
        }
        
        self.log(f"Query from {addr}: {domain} ({qtype_name}) [RD={recursion_desired}]")
        
        # Track query type
        if recursion_desired:
            self.stats['recursive_queries'] += 1
        else:
            self.stats['iterative_queries'] += 1
        
        # Step 1: Check local records
        local_start = time.time()
        local_result = self.check_local_records(domain, qtype)
        if local_result:
            rtt = (time.time() - local_start) * 1000
            total_time = (time.time() - start_time) * 1000
            
            self.stats['successful_resolutions'] += 1
            self.stats['local_resolutions'] += 1
            self.stats['total_latency_ms'] += total_time
            
            log_entry.update({
                'resolution_mode': 'Local Records',
                'dns_server_contacted': 'localhost',
                'step': 'Local',
                'response': local_result,
                'rtt_ms': round(rtt, 2),
                'total_time_ms': round(total_time, 2),
                'cache_status': 'N/A',
                'status': 'SUCCESS'
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
            total_time = (time.time() - start_time) * 1000
            
            self.stats['successful_resolutions'] += 1
            self.stats['cache_resolutions'] += 1
            self.stats['total_latency_ms'] += total_time
            
            log_entry.update({
                'resolution_mode': 'Cache',
                'dns_server_contacted': 'cache',
                'step': 'Cache',
                'response': 'Cached response',
                'rtt_ms': round(rtt, 2),
                'total_time_ms': round(total_time, 2),
                'cache_status': 'HIT',
                'status': 'SUCCESS'
            })
            self.log(f"Found in cache: {domain}")
            self.save_log(log_entry)
            self.socket.sendto(cached_response, addr)
            return
        
        log_entry['cache_status'] = 'MISS'
        
        # Step 3: Decide resolution mode
        if recursion_desired and self.supports_recursion:
            # Recursive resolution: Server does all the work
            self.log(f"Performing RECURSIVE resolution for {domain}")
            log_entry['resolution_mode'] = 'Recursive'
            
            for dns_server in self.external_dns:
                self.log(f"Forwarding to external DNS (recursive): {dns_server}")
                ext_start = time.time()
                response = self.query_external_dns_recursive(data, dns_server)
                rtt = (time.time() - ext_start) * 1000
                total_time = (time.time() - start_time) * 1000
                
                if response:
                    self.stats['successful_resolutions'] += 1
                    self.stats['external_resolutions'] += 1
                    self.stats['total_latency_ms'] += total_time
                    
                    log_entry.update({
                        'dns_server_contacted': dns_server,
                        'step': 'Recursive External',
                        'response': 'Resolved',
                        'rtt_ms': round(rtt, 2),
                        'total_time_ms': round(total_time, 2),
                        'status': 'SUCCESS'
                    })
                    self.log(f"Resolved recursively via {dns_server}: {domain}")
                    self.save_log(log_entry)
                    
                    # Cache the response
                    cache_key = f"{domain}:{qtype}"
                    self.cache.set(cache_key, response, ttl=300)
                    
                    self.socket.sendto(response, addr)
                    return
        else:
            # Iterative resolution or fallback
            if recursion_desired and not self.supports_recursion:
                self.log(f"Recursion requested but not supported, falling back to iterative")
                log_entry['resolution_mode'] = 'Iterative (fallback)'
            else:
                self.log(f"Performing ITERATIVE resolution for {domain}")
                log_entry['resolution_mode'] = 'Iterative'
            
            ext_start = time.time()
            response = self.resolve_iteratively(domain, qtype)
            rtt = (time.time() - ext_start) * 1000
            total_time = (time.time() - start_time) * 1000
            
            if response:
                self.stats['successful_resolutions'] += 1
                self.stats['external_resolutions'] += 1
                self.stats['total_latency_ms'] += total_time
                
                log_entry.update({
                    'dns_server_contacted': 'Multiple (iterative)',
                    'step': 'Iterative External',
                    'response': 'Resolved',
                    'rtt_ms': round(rtt, 2),
                    'total_time_ms': round(total_time, 2),
                    'status': 'SUCCESS'
                })
                self.log(f"Resolved iteratively: {domain}")
                self.save_log(log_entry)
                
                # Cache the response
                cache_key = f"{domain}:{qtype}"
                self.cache.set(cache_key, response, ttl=300)
                
                self.socket.sendto(response, addr)
                return
        
        # Failed to resolve
        total_time = (time.time() - start_time) * 1000
        self.stats['failed_resolutions'] += 1
        self.stats['total_latency_ms'] += total_time
        
        log_entry.update({
            'dns_server_contacted': 'None',
            'step': 'Failed',
            'response': 'No response',
            'rtt_ms': 0,
            'total_time_ms': round(total_time, 2),
            'status': 'FAILED'
        })
        self.log(f"Failed to resolve: {domain}")
        self.save_log(log_entry)
    
    def print_statistics(self):
        """Print server statistics"""
        cache_stats = self.cache.get_stats()
        
        avg_latency = (self.stats['total_latency_ms'] / self.stats['total_queries'] 
                      if self.stats['total_queries'] > 0 else 0)
        
        print("\n" + "=" * 70)
        print("DNS SERVER STATISTICS (RECURSIVE MODE)")
        print("=" * 70)
        print(f"Total Queries: {self.stats['total_queries']}")
        print(f"Successful Resolutions: {self.stats['successful_resolutions']}")
        print(f"Failed Resolutions: {self.stats['failed_resolutions']}")
        print(f"Recursive Queries: {self.stats['recursive_queries']}")
        print(f"Iterative Queries: {self.stats['iterative_queries']}")
        print(f"\nResolution Sources:")
        print(f"  Local Records: {self.stats['local_resolutions']}")
        print(f"  Cache: {self.stats['cache_resolutions']}")
        print(f"  External DNS: {self.stats['external_resolutions']}")
        print(f"\nCache Statistics:")
        print(f"  Cache Hits: {cache_stats['hits']}")
        print(f"  Cache Misses: {cache_stats['misses']}")
        print(f"  Cache Hit Rate: {cache_stats['hit_percentage']}%")
        print(f"\nPerformance:")
        print(f"  Average Lookup Latency: {round(avg_latency, 2)} ms")
        print("=" * 70)
        
        # Save statistics to file
        stats_output = {
            'server_stats': self.stats,
            'cache_stats': cache_stats,
            'average_lookup_latency_ms': round(avg_latency, 2),
            'cache_hit_percentage': cache_stats['hit_percentage']
        }
        with open('dns_server_stats_recursive.json', 'w') as f:
            json.dump(stats_output, f, indent=2)
    
    def start(self):
        """Start DNS server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', self.port))
        
        self.log(f"DNS Server started on port {self.port}")
        self.log(f"Recursion Support: {'ENABLED' if self.supports_recursion else 'DISABLED'}")
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
            self.print_statistics()
        finally:
            self.socket.close()

def main():
    parser = argparse.ArgumentParser(description='DNS Server with Recursive Resolution Support')
    parser.add_argument('-p', '--port', type=int, default=5353, 
                       help='Port to listen on (default: 5353)')
    parser.add_argument('-d', '--dns', nargs='+', default=['8.8.8.8', '1.1.1.1'], 
                       help='External DNS servers (default: 8.8.8.8 1.1.1.1)')
    parser.add_argument('-r', '--records', default='dns_records.json',
                       help='DNS records file (default: dns_records.json)')
    parser.add_argument('--no-recursion', action='store_true',
                       help='Disable recursion support (server will only do iterative)')
    
    args = parser.parse_args()
    
    server = RecursiveDNSServer(
        port=args.port, 
        external_dns=args.dns, 
        records_file=args.records,
        supports_recursion=not args.no_recursion
    )
    server.start()

if __name__ == '__main__':
    main()