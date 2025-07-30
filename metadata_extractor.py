#!/usr/bin/env python3
"""
DNS-over-TLS (DoT) PCAP Metadata Extractor - Improved Version
Analyzes DoT responses from a PCAP file and extracts metadata
"""

import argparse
import struct
import socket
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP, IPv6, DNS, Raw
    from scapy.layers.tls.all import TLS, TLSApplicationData
except ImportError:
    print("Error: Scapy is not installed. Install it with: pip install scapy")
    exit(1)

class DoTAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.dot_responses = []
        self.stats = defaultdict(int)
        
    def analyze_pcap(self):
        """Analyzes the PCAP file and extracts DoT responses"""
        print(f"Analyzing PCAP file: {self.pcap_file}")
        
        try:
            packets = rdpcap(self.pcap_file)
        except Exception as e:
            print(f"Error while loading the PCAP file: {e}")
            return
        
        print(f"Packets loaded: {len(packets)}")
        
        for i, packet in enumerate(packets):
            print(f"Packet {i}: {packet.summary()}")
            
            # Debug: Show all layers
            print(f"  Layers: {[layer.name for layer in packet.layers()]}")
            
            if self.is_dot_packet(packet):
                print(f"  -> DoT packet detected!")
                self.process_dot_packet(packet, i)
            else:
                print(f"  -> Not a DoT packet")
        
        print(f"\nFound DoT responses: {len(self.dot_responses)}")
        
    def is_dot_packet(self, packet):
        """Checks if a packet is a DoT packet (Port 853 TCP with potential TLS/encrypted data)"""
        if not packet.haslayer(TCP):
            return False
            
        tcp_layer = packet[TCP]
        
        # Check for port 853 (DoT port)
        is_port_853 = (tcp_layer.sport == 853 or tcp_layer.dport == 853)
        
        if not is_port_853:
            return False
        
        # Check if packet has payload (not just TCP handshake)
        has_payload = len(tcp_layer.payload) > 0
        
        # DoT packets can have TLS layer or Raw data (encrypted)
        has_tls_or_data = packet.haslayer(TLS) or packet.haslayer(Raw) or packet.haslayer(TLSApplicationData)
        
        print(f"    Port 853: {is_port_853}, Has payload: {has_payload}, Has TLS/Data: {has_tls_or_data}")
        
        return is_port_853 and (has_payload or has_tls_or_data)
    
    def process_dot_packet(self, packet, packet_num):
        """Processes a DoT packet and extracts DNS data"""
        self.stats['total_dot_packets'] += 1
        
        # Basic packet information
        timestamp = datetime.fromtimestamp(float(packet.time))
        
        # IP information
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_version = 4
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            ip_version = 6
        else:
            return
        
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        
        print(f"    Processing DoT packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Try different approaches to extract DNS data
        dns_data = None
        data_source = "unknown"
        
        # Method 1: TLS Application Data
        if packet.haslayer(TLSApplicationData):
            print("    Trying TLS Application Data...")
            tls_data = packet[TLSApplicationData]
            dns_data = self.extract_dns_from_tls(tls_data.data)
            data_source = "TLS"
            
        # Method 2: Raw data (might be encrypted or plain)
        elif packet.haslayer(Raw):
            print("    Trying Raw data...")
            raw_data = packet[Raw].load
            dns_data = self.extract_dns_from_raw(raw_data)
            data_source = "Raw"
            
        # Method 3: TCP payload
        elif len(tcp_layer.payload) > 0:
            print("    Trying TCP payload...")
            payload = bytes(tcp_layer.payload)
            dns_data = self.extract_dns_from_raw(payload)
            data_source = "TCP"
        
        if dns_data:
            try:
                dns_packet = DNS(dns_data)
                print(f"    DNS packet parsed successfully from {data_source}")
                
                # Check if it's a response
                if dns_packet.qr == 1:  # qr=1 means response
                    self.stats['dns_responses'] += 1
                    
                    metadata = {
                        'packet_number': packet_num,
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'ip_version': ip_version,
                        'data_source': data_source,
                        'dns_id': dns_packet.id,
                        'query_count': dns_packet.qdcount,
                        'answer_count': dns_packet.ancount,
                        'authority_count': dns_packet.nscount,
                        'additional_count': dns_packet.arcount,
                        'response_code': dns_packet.rcode,
                        'queries': [],
                        'answers': [],
                        'raw_data_length': len(dns_data)
                    }
                    
                    # Extract queries
                    if dns_packet.qdcount > 0 and hasattr(dns_packet, 'qd'):
                        query = dns_packet.qd
                        if query:
                            metadata['queries'].append({
                                'name': query.qname.decode() if query.qname else '',
                                'type': query.qtype,
                                'class': query.qclass
                            })
                    
                    # Extract answers
                    if dns_packet.ancount > 0 and hasattr(dns_packet, 'an'):
                        answers = dns_packet.an if isinstance(dns_packet.an, list) else [dns_packet.an]
                        for answer in answers:
                            if answer:
                                metadata['answers'].append({
                                    'name': answer.rrname.decode() if hasattr(answer, 'rrname') and answer.rrname else '',
                                    'type': answer.type if hasattr(answer, 'type') else 0,
                                    'class': answer.rclass if hasattr(answer, 'rclass') else 0,
                                    'ttl': answer.ttl if hasattr(answer, 'ttl') else 0,
                                    'data_length': answer.rdlen if hasattr(answer, 'rdlen') else 0
                                })
                    
                    self.dot_responses.append(metadata)
                    print(f"    -> DNS response added to results")
                else:
                    print(f"    -> DNS query (not response)")
                    self.stats['dns_queries'] += 1
                    
            except Exception as e:
                print(f"    DNS parsing failed: {e}")
                self.stats['parsing_errors'] += 1
                
                # Store as encrypted/unparseable packet
                metadata = {
                    'packet_number': packet_num,
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'ip_version': ip_version,
                    'data_source': data_source,
                    'status': 'encrypted_or_corrupted',
                    'raw_data_length': len(dns_data) if dns_data else 0
                }
                self.dot_responses.append(metadata)
        else:
            print(f"    No DNS data found")
            self.stats['no_dns_data'] += 1
    
    def extract_dns_from_tls(self, tls_data):
        """Attempts to extract DNS data from TLS application data"""
        if len(tls_data) < 2:
            return None
        
        try:
            # DoT uses a 2-byte length prefix for DNS messages
            dns_length = struct.unpack('!H', tls_data[:2])[0]
            
            if len(tls_data) >= dns_length + 2:
                return tls_data[2:2+dns_length]
        except:
            pass
        
        # Fallback: try to interpret data directly as DNS
        return tls_data
    
    def extract_dns_from_raw(self, raw_data):
        """Attempts to extract DNS data from raw packet data"""
        if len(raw_data) < 12:  # Minimum DNS header size
            return None
        
        # Try different approaches
        approaches = [
            raw_data,  # Direct interpretation
            raw_data[2:] if len(raw_data) > 2 else None,  # Skip 2-byte length prefix
            raw_data[4:] if len(raw_data) > 4 else None,  # Skip 4-byte prefix
        ]
        
        for data in approaches:
            if data and len(data) >= 12:
                try:
                    # Quick check if it looks like DNS
                    header = struct.unpack('!HHHHHH', data[:12])
                    dns_id, flags, qdcount, ancount, nscount, arcount = header
                    
                    # Basic sanity checks
                    if qdcount <= 100 and ancount <= 100 and nscount <= 100 and arcount <= 100:
                        return data
                except:
                    continue
        
        return None
    
    def print_statistics(self):
        """Print statistics"""
        print("\n" + "="*60)
        print("STATISTICS")
        print("="*60)
        print(f"Total DoT packets: {self.stats['total_dot_packets']}")
        print(f"DNS responses found: {self.stats['dns_responses']}")
        print(f"DNS queries found: {self.stats['dns_queries']}")
        print(f"Parsing errors: {self.stats['parsing_errors']}")
        print(f"No DNS data found: {self.stats['no_dns_data']}")
    
    def print_metadata(self, detailed=False):
        """Print the extracted metadata"""
        print("\n" + "="*60)
        print("DOT RESPONSE METADATA")
        print("="*60)
        
        for i, response in enumerate(self.dot_responses, 1):
            print(f"\n--- Response {i} ---")
            print(f"Packet number: {response['packet_number']}")
            print(f"Timestamp: {response['timestamp']}")
            print(f"Source: {response['src_ip']}:{response['src_port']}")
            print(f"Destination: {response['dst_ip']}:{response['dst_port']}")
            print(f"IP version: IPv{response['ip_version']}")
            print(f"Data source: {response.get('data_source', 'unknown')}")
            
            if 'status' in response:
                print(f"Status: {response['status']}")
                print(f"Raw data length: {response['raw_data_length']} bytes")
            else:
                print(f"DNS ID: {response['dns_id']}")
                print(f"Response code: {response['response_code']}")
                print(f"Queries: {response['query_count']}")
                print(f"Answers: {response['answer_count']}")
                print(f"Authority: {response['authority_count']}")
                print(f"Additional: {response['additional_count']}")
                print(f"Raw data length: {response['raw_data_length']} bytes")
                
                if detailed:
                    if response['queries']:
                        print("Queries:")
                        for query in response['queries']:
                            print(f"  - {query['name']} (Type: {query['type']}, Class: {query['class']})")
                    
                    if response['answers']:
                        print("Answers:")
                        for answer in response['answers']:
                            print(f"  - {answer['name']} (Type: {answer['type']}, TTL: {answer['ttl']}s)")
    
    def export_to_csv(self, filename):
        """Export metadata to a CSV file"""
        import csv
        
        print(f"\nExporting metadata to: {filename}")
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'packet_number', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'ip_version', 'data_source', 'status', 'dns_id', 'query_count', 'answer_count', 
                'authority_count', 'additional_count', 'response_code', 'raw_data_length', 
                'queries', 'answers'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for response in self.dot_responses:
                row = response.copy()
                # Convert lists to strings for CSV
                if 'queries' in response:
                    row['queries'] = '; '.join([f"{q['name']}({q['type']})" for q in response['queries']])
                if 'answers' in response:
                    row['answers'] = '; '.join([f"{a['name']}({a['type']})" for a in response['answers']])
                writer.writerow(row)
        
        print(f"Export completed: {len(self.dot_responses)} entries")

def main():
    parser = argparse.ArgumentParser(description='DoT PCAP Metadata Extractor')
    parser.add_argument('pcap_file', help='Path to the PCAP file')
    parser.add_argument('-d', '--detailed', action='store_true', 
                       help='Show detailed information about queries and answers')
    parser.add_argument('-o', '--output', help='Export metadata to CSV file')
    
    args = parser.parse_args()
    
    # Analyze PCAP
    analyzer = DoTAnalyzer(args.pcap_file)
    analyzer.analyze_pcap()
    
    # Show results
    analyzer.print_statistics()
    analyzer.print_metadata(detailed=args.detailed)
    
    # Optional: CSV export
    if args.output:
        analyzer.export_to_csv(args.output)

if __name__ == "__main__":
    main()