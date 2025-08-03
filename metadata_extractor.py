#!/usr/bin/env python3
"""
DoT (DNS over TLS) PCAP Analyzer
Extracts metadata from PCAP files containing DoT communication
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
import statistics

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
            print(f"Loading PCAP file: {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
            print(f"Number of packets loaded: {len(self.packets)}")
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
            sys.exit(1)
    
    def is_dot_traffic(self, packet):
        """Checks if a packet is DoT traffic (port 853)"""
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            return tcp_layer.sport == 853 or tcp_layer.dport == 853
        return False
    
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
        print("Analyzing DoT traffic...")
        
        dot_packets = 0
        for packet in self.packets:
            if self.is_dot_traffic(packet):
                dot_packets += 1
                self.analyze_dot_patterns(packet)
        
        print(f"DoT packets found: {dot_packets}")
        
        if dot_packets == 0:
            print("Warning: No DoT packets (port 853) found!")
            return
        
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
    
    def print_results(self, results):
        """Prints the results in a formatted way"""
        print("\n" + "="*60)
        print("DoT ANALYSIS RESULTS")
        print("="*60)
        print(f"File: {results['file']}")
        print(f"Analysis Time: {results['analysis_time']}")
        
        print(f"\n📊 DNS QUERIES:")
        print(f"  Total: {results['total_dns_queries']}")
        print(f"  Unique Clients: {results['unique_clients']}")
        
        print(f"\n📈 QUERIES PER CLIENT:")
        for client_ip, count in results['dns_queries_per_client'].items():
            print(f"  {client_ip}: {count} queries")
        
        print(f"\n📦 PACKET SIZES:")
        req = results['packet_sizes']['requests']
        resp = results['packet_sizes']['responses']
        
        print(f"  Requests:")
        print(f"    Count: {req['count']}")
        print(f"    Average: {req['average']:.1f} bytes")
        print(f"    Min/Max: {req['min']}/{req['max']} bytes")
        
        print(f"  Responses:")
        print(f"    Count: {resp['count']}")
        print(f"    Average: {resp['average']:.1f} bytes")
        print(f"    Min/Max: {resp['min']}/{resp['max']} bytes")
        
        duration = results['communication_duration']
        print(f"\n⏱️  COMMUNICATION DURATION:")
        print(f"  Start: {datetime.fromtimestamp(duration['start_time'])}")
        print(f"  End: {datetime.fromtimestamp(duration['end_time'])}")
        print(f"  Duration: {duration['duration_seconds']:.2f} seconds")


def main():
    parser = argparse.ArgumentParser(
        description='Analyzes DoT (DNS over TLS) communication from PCAP files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dot_analyzer.py sample.pcap
  python dot_analyzer.py sample.pcap --json results.json
  python dot_analyzer.py sample.pcap --verbose
        """
    )
    
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--json', '-j', help='Save results as JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Create and run analyzer
    analyzer = DoTAnalyzer(args.pcap_file)
    analyzer.load_pcap()
    results = analyzer.analyze()
    
    if results:
        analyzer.print_results(results)
        
        # JSON export if requested
        if args.json:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 Results saved to: {args.json}")
    
    print("\n✅ Analysis completed!")


if __name__ == "__main__":
    main()