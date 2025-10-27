#!/usr/bin/env python3
"""
Script to Modify PCAP Files - Set Recursive Mode Flag to True
This script reads PCAP files and modifies DNS queries to set the RD (Recursion Desired) flag
"""

import os
import sys

try:
    from scapy.all import rdpcap, wrpcap, DNS, DNSQR, IP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Error: scapy not installed. Install with: pip install scapy")
    exit(1)

def modify_pcap_set_recursive_flag(input_pcap, output_pcap=None):
    """
    Read a PCAP file and modify all DNS queries to set the RD (Recursion Desired) flag
    
    Args:
        input_pcap: Path to input PCAP file
        output_pcap: Path to output PCAP file (if None, will append '_recursive' to input name)
    
    Returns:
        Number of packets modified
    """
    if not output_pcap:
        base_name = input_pcap.replace('.pcap', '')
        output_pcap = f"{base_name}_recursive.pcap"
    
    print(f"\n{'='*80}")
    print(f"MODIFYING PCAP FILE - SETTING RECURSIVE MODE FLAG")
    print(f"{'='*80}")
    print(f"Input File:  {input_pcap}")
    print(f"Output File: {output_pcap}")
    print(f"{'='*80}\n")
    
    # Read packets
    print("Reading PCAP file...")
    try:
        packets = rdpcap(input_pcap)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return 0
    
    print(f"Total packets: {len(packets)}")
    
    # Modify DNS queries
    modified_packets = []
    dns_query_count = 0
    modified_count = 0
    
    for i, packet in enumerate(packets):
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_layer = packet[DNS]
            
            # Check if it's a query (qr=0)
            if dns_layer.qr == 0:
                dns_query_count += 1
                
                # Check if RD flag is already set
                rd_before = bool(dns_layer.rd)
                
                # Set the RD (Recursion Desired) flag
                dns_layer.rd = 1
                
                # Recalculate checksums
                if packet.haslayer(IP):
                    del packet[IP].chksum
                if packet.haslayer(UDP):
                    del packet[UDP].chksum
                
                rd_after = bool(dns_layer.rd)
                
                if not rd_before and rd_after:
                    modified_count += 1
                    domain = dns_layer[DNSQR].qname.decode('utf-8').rstrip('.')
                    print(f"  [{dns_query_count}] Modified: {domain} (RD: {rd_before} -> {rd_after})")
                elif rd_before:
                    print(f"  [{dns_query_count}] Already set: {dns_layer[DNSQR].qname.decode('utf-8').rstrip('.')} (RD: {rd_before})")
        
        modified_packets.append(packet)
    
    # Write modified packets
    print(f"\nWriting modified PCAP file...")
    try:
        wrpcap(output_pcap, modified_packets)
        print(f"Successfully wrote {len(modified_packets)} packets to {output_pcap}")
    except Exception as e:
        print(f"Error writing PCAP file: {e}")
        return 0
    
    # Summary
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Total Packets:       {len(packets)}")
    print(f"DNS Query Packets:   {dns_query_count}")
    print(f"Modified Packets:    {modified_count}")
    print(f"Already Set:         {dns_query_count - modified_count}")
    print(f"{'='*80}\n")
    
    return modified_count

def modify_all_pcaps_in_directory(directory):
    """
    Modify all PCAP files in a directory to set recursive flag
    
    Args:
        directory: Path to directory containing PCAP files
    """
    pcap_files = [f for f in os.listdir(directory) if f.endswith('.pcap') and not f.endswith('_recursive.pcap')]
    
    if not pcap_files:
        print(f"No PCAP files found in {directory}")
        return
    
    print(f"\nFound {len(pcap_files)} PCAP files to modify:")
    for f in pcap_files:
        print(f"  - {f}")
    print()
    
    total_modified = 0
    for pcap_file in pcap_files:
        input_path = os.path.join(directory, pcap_file)
        output_path = os.path.join(directory, pcap_file.replace('.pcap', '_recursive.pcap'))
        
        modified = modify_pcap_set_recursive_flag(input_path, output_path)
        total_modified += modified
    
    print(f"\n{'='*80}")
    print(f"COMPLETED - Total packets modified across all files: {total_modified}")
    print(f"{'='*80}\n")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Single file:  python modify_pcap_recursive.py <pcap_file>")
        print("  Directory:    python modify_pcap_recursive.py --dir <directory>")
        print("\nExamples:")
        print("  python modify_pcap_recursive.py PCAP_1_H1_f.pcap")
        print("  python modify_pcap_recursive.py --dir PCAPs_DNS_Resolver/")
        sys.exit(1)
    
    if sys.argv[1] == '--dir':
        if len(sys.argv) < 3:
            print("Error: Directory path required")
            print("Usage: python modify_pcap_recursive.py --dir <directory>")
            sys.exit(1)
        
        directory = sys.argv[2]
        if not os.path.isdir(directory):
            print(f"Error: {directory} is not a valid directory")
            sys.exit(1)
        
        modify_all_pcaps_in_directory(directory)
    else:
        pcap_file = sys.argv[1]
        if not os.path.isfile(pcap_file):
            print(f"Error: {pcap_file} not found")
            sys.exit(1)
        
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        modify_pcap_set_recursive_flag(pcap_file, output_file)

if __name__ == '__main__':
    main()
