#!/usr/bin/env python3
import dns.message
import dns.query
import dns.rdatatype
import time
import pandas as pd
import subprocess
import os
import signal
import sys

class DNSMonitor:
    def __init__(self):
        self.tcpdump_processes = []
        signal.signal(signal.SIGINT, self.cleanup)
    
    def cleanup(self, signum=None, frame=None):
        """Clean up tcpdump processes on exit"""
        print("\nCleaning up...")
        for proc in self.tcpdump_processes:
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait()
        sys.exit(0)
    
    def process_csv(self, csv_file):
        try:
            df = pd.read_csv(csv_file, header=None, usecols=[1])
            return df[1].tolist()
        except Exception as e:
            print(f"CSV error: {e}")
            return []
    

    
    def resolve_dot(self, domain, server='127.0.0.1', port=853):
        """DNS over TLS query via local proxy without cert verification"""
        try:
            query = dns.message.make_query(domain, dns.rdatatype.A)
            
            # Connect to local DNS proxy without certificate verification
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            response = dns.query.tls(query, server, port=port, timeout=10, ssl_context=context)
            
            ips = []
            if response.answer:
                for ans in response.answer:
                    for item in ans.items:
                        ips.append(str(item))
            
            return ips
            
        except Exception as e:
            print(f"DoT error for {domain}: {e}")
            return []
    
    def run_tcpdump(self, interface='eth0', output_file='/tmp/dot.pcap'):
        """Start tcpdump with better error handling"""
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            cmd = [
                'tcpdump', '-i', interface, '-w', output_file,
                '-s', '0', 'port', '853'
            ]
            
            with open(os.devnull, 'w') as devnull:
                process = subprocess.Popen(cmd, stdout=devnull, stderr=devnull)
            
            self.tcpdump_processes.append(process)
            print(f"Started capture: {output_file}")
            return process
            
        except Exception as e:
            print(f"TCPDump error: {e}")
            return None
    
    def monitor_domains(self, csv_files, capture_time=10):
        """Main monitoring function"""
        for csv_file in csv_files:
            if not os.path.exists(csv_file):
                print(f"File not found: {csv_file}")
                continue
                
            print(f"\nProcessing {csv_file}")
            domains = self.process_csv(csv_file)
            
            if not domains:
                print(f"No domains found in {csv_file}")
                continue
            
            # Create output directory
            filename = os.path.splitext(os.path.basename(csv_file))[0]
            output_dir = f"./captures/{filename}"
            os.makedirs(output_dir, exist_ok=True)
            
            for i, domain in enumerate(domains, 1):
                print(f"[{i}/{len(domains)}] Processing {domain}")
                
                # Start packet capture
                pcap_file = f"{output_dir}/dot_{domain.replace('.', '_')}.pcap"
                dump_proc = self.run_tcpdump(output_file=pcap_file)
                
                if dump_proc:
                    time.sleep(1)  # Let tcpdump start
                    
                    # Perform DNS query
                    ips = self.resolve_dot(domain)
                    print(f"  {domain} -> {ips if ips else 'No response'}")
                    
                    # Wait for capture
                    time.sleep(capture_time)
                    
                    # Stop capture
                    dump_proc.terminate()
                    dump_proc.wait()
                    self.tcpdump_processes.remove(dump_proc)
                    print(f"  Capture saved: {pcap_file}")
                else:
                    print(f"  Failed to start capture for {domain}")

def main():
    # Configuration
    csv_files = [
        "./data/categories/news.csv"
        "./data/categories/banking.csv",
        "./data/categories/streaming.csv", 
    ]
    
    monitor = DNSMonitor()
    
    try:
        monitor.monitor_domains(
            csv_files=csv_files,
            capture_time=30  # 30 seconds capture time
        )
    except KeyboardInterrupt:
        monitor.cleanup()

if __name__ == "__main__":
    main()