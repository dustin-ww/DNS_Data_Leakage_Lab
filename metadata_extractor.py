#!/usr/bin/env python3
"""
DoT (DNS over TLS) PCAP Analyzer
Extracts metadata from PCAP files containing DoT communication
Processes directories with category subfolders and generates CSV files
"""

import argparse
import json
import sys
import csv
from collections import defaultdict
from datetime import datetime
import statistics
import os
import glob

try:
    from scapy.all import rdpcap, TCP, IP, IPv6, DNS
    from scapy.layers.tls.all import TLS
except ImportError:
    print("Error: Scapy is not installed. Install it with:")
    print("pip install scapy")
    sys.exit(1)


class DoTAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.dns_queries = defaultdict(int)  # IP -> Number of queries
        self.request_sizes = []
        self.response_sizes = []
        self.timestamps = []
        
    def load_pcap(self):
        """Loads the PCAP file"""
        try:
            if self.verbose:
                print(f"Loading PCAP file: {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
            if self.verbose:
                print(f"Number of packets loaded: {len(self.packets)}")
        except Exception as e:
            print(f"Error loading PCAP file {self.pcap_file}: {e}")
            return False
        return True
    
    def set_verbose(self, verbose):
        """Set verbose mode"""
        self.verbose = verbose
    
    def is_dot_traffic(self, packet):
        """Checks if a packet is DoT traffic (port 853)"""
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            return tcp_layer.sport == 853 or tcp_layer.dport == 853
        return False
    
    def extract_website_from_filename(self, filename):
        """Extract website name from filename (e.g., dot_hulu_com.pcap -> hulu)"""
        basename = os.path.basename(filename)
        if basename.startswith('dot_') and basename.endswith('.pcap'):
            # Remove 'dot_' prefix and '.pcap' suffix
            domain_part = basename[4:-5]
            # Split by underscore and take the first part as website name
            parts = domain_part.split('_')
            if len(parts) > 0:
                return parts[0]
        return basename.replace('.pcap', '')
    
    def extract_dns_from_tls(self, packet):
        """Attempts to extract DNS data from TLS-encrypted packets"""
        # Since DoT is encrypted, we cannot directly read DNS content
        # We need to rely on packet sizes and timing information
        return None
    
    def analyze_dot_patterns(self, packet):
        """Analyzes DoT traffic patterns based on packet sizes and timing"""
        if not packet.haslayer(TCP):
            return
        
        tcp_layer = packet[TCP]
        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        
        # Capture timestamp
        timestamp = float(packet.time)
        self.timestamps.append(timestamp)
        
        # Packet size (TCP payload)
        payload_size = len(tcp_layer.payload) if tcp_layer.payload else 0
        
        # Distinguish between request and response based on port
        if tcp_layer.dport == 853:  # Request to DoT server
            if payload_size > 0:  # Only count packets with payload
                self.request_sizes.append(payload_size)
                # Count DNS query (heuristic: each packet with payload > 50 bytes)
                if payload_size > 50:
                    client_ip = ip_layer.src
                    self.dns_queries[client_ip] += 1
        
        elif tcp_layer.sport == 853:  # Response from DoT server
            if payload_size > 0:
                self.response_sizes.append(payload_size)
    
    def analyze(self):
        """Performs the main analysis"""
        if not self.load_pcap():
            return None
            
        if self.verbose:
            print(f"Analyzing DoT traffic for {self.pcap_file}...")
        
        dot_packets = 0
        for packet in self.packets:
            if self.is_dot_traffic(packet):
                dot_packets += 1
                self.analyze_dot_patterns(packet)
        
        if self.verbose:
            print(f"DoT packets found: {dot_packets}")
        
        if dot_packets == 0:
            if self.verbose:
                print(f"Warning: No DoT packets (port 853) found in {self.pcap_file}!")
            return None
        
        # Calculate results
        results = self.calculate_results()
        return results
    
    def calculate_results(self):
        """Calculates the final metadata"""
        results = {
            'file': self.pcap_file,
            'analysis_time': datetime.now().isoformat(),
            'dns_queries_per_client': dict(self.dns_queries),
            'total_dns_queries': sum(self.dns_queries.values()),
            'unique_clients': len(self.dns_queries),
            'packet_sizes': {
                'requests': {
                    'count': len(self.request_sizes),
                    'average': statistics.mean(self.request_sizes) if self.request_sizes else 0,
                    'min': min(self.request_sizes) if self.request_sizes else 0,
                    'max': max(self.request_sizes) if self.request_sizes else 0
                },
                'responses': {
                    'count': len(self.response_sizes),
                    'average': statistics.mean(self.response_sizes) if self.response_sizes else 0,
                    'min': min(self.response_sizes) if self.response_sizes else 0,
                    'max': max(self.response_sizes) if self.response_sizes else 0
                }
            },
            'communication_duration': {
                'start_time': min(self.timestamps) if self.timestamps else 0,
                'end_time': max(self.timestamps) if self.timestamps else 0,
                'duration_seconds': max(self.timestamps) - min(self.timestamps) if len(self.timestamps) > 1 else 0
            }
        }
        
        return results


def process_directory(input_dir, output_dir, verbose=False):
    """Process all subdirectories in the input directory"""
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Find all subdirectories
    subdirs = [d for d in os.listdir(input_dir) 
               if os.path.isdir(os.path.join(input_dir, d))]
    
    if not subdirs:
        print(f"No subdirectories found in {input_dir}")
        return
    
    print(f"Found subdirectories: {', '.join(subdirs)}")
    
    for subdir in subdirs:
        print(f"\nProcessing category: {subdir}")
        subdir_path = os.path.join(input_dir, subdir)
        
        # Find all .pcap files in the subdirectory
        pcap_files = glob.glob(os.path.join(subdir_path, "*.pcap"))
        
        if not pcap_files:
            print(f"No PCAP files found in {subdir_path}")
            continue
        
        print(f"Found {len(pcap_files)} PCAP files in {subdir}")
        
        # Create CSV file for this category
        csv_filename = os.path.join(output_dir, f"{subdir}.csv")
        
        # CSV header
        csv_headers = [
            'category',
            'website',
            'filename',
            'total_dns_queries',
            'unique_clients',
            'request_count',
            'request_avg_size',
            'request_min_size',
            'request_max_size',
            'response_count',
            'response_avg_size',
            'response_min_size',
            'response_max_size',
            'duration_seconds',
            'analysis_time'
        ]
        
        # Process each PCAP file
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(csv_headers)
            
            for pcap_file in pcap_files:
                if verbose:
                    print(f"  Processing: {os.path.basename(pcap_file)}")
                
                # Create analyzer for this file
                analyzer = DoTAnalyzer(pcap_file)
                analyzer.set_verbose(verbose)
                
                # Extract website name from filename
                website = analyzer.extract_website_from_filename(pcap_file)
                
                # Analyze the file
                results = analyzer.analyze()
                
                if results:
                    # Write results to CSV
                    row = [
                        subdir,  # category
                        website,  # website
                        os.path.basename(pcap_file),  # filename
                        results['total_dns_queries'],
                        results['unique_clients'],
                        results['packet_sizes']['requests']['count'],
                        round(results['packet_sizes']['requests']['average'], 2),
                        results['packet_sizes']['requests']['min'],
                        results['packet_sizes']['requests']['max'],
                        results['packet_sizes']['responses']['count'],
                        round(results['packet_sizes']['responses']['average'], 2),
                        results['packet_sizes']['responses']['min'],
                        results['packet_sizes']['responses']['max'],
                        round(results['communication_duration']['duration_seconds'], 2),
                        results['analysis_time']
                    ]
                    writer.writerow(row)
                    
                    if verbose:
                        print(f"    ✓ Analyzed: {website} - {results['total_dns_queries']} queries")
                else:
                    # Write row with zeros if no DoT traffic found
                    row = [
                        subdir,  # category
                        website,  # website
                        os.path.basename(pcap_file),  # filename
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # all zeros
                        datetime.now().isoformat()
                    ]
                    writer.writerow(row)
                    
                    if verbose:
                        print(f"    ⚠ No DoT traffic found in: {website}")
        
        print(f"✓ Created CSV file: {csv_filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyzes DoT (DNS over TLS) communication from PCAP files in directory structure',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dot_analyzer.py ./input ./output
  python dot_analyzer.py ./input ./output --verbose
  
Expected directory structure:
  input/
    ├── banking/
    │   ├── dot_bank1_com.pcap
    │   └── dot_bank2_com.pcap
    ├── news/
    │   ├── dot_cnn_com.pcap
    │   └── dot_bbc_com.pcap
    └── streaming/
        ├── dot_hulu_com.pcap
        └── dot_netflix_com.pcap
        """
    )
    
    parser.add_argument('input_dir', help='Path to input directory with category subfolders')
    parser.add_argument('output_dir', help='Directory to save output CSV files', nargs='?', default='./')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Check if input directory exists
    if not os.path.exists(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' does not exist!")
        sys.exit(1)
    
    # Process the directory structure
    process_directory(args.input_dir, args.output_dir, args.verbose)
    
    print("\n✅ Analysis completed!")


if __name__ == "__main__":
    main()