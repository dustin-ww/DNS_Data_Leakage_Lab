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
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class DNSMonitor:
    def __init__(self):
        self.tcpdump_processes = []
        self.driver = None
        signal.signal(signal.SIGINT, self.cleanup)
        self.setup_selenium()
    
    def setup_selenium(self):
        """Setup Selenium WebDriver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")  # Headless mode
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            print("Selenium WebDriver initialized")
        except Exception as e:
            print(f"Selenium setup error: {e}")
            self.driver = None
    
    def cleanup(self, signum=None, frame=None):
        """Clean up tcpdump processes and selenium on exit"""
        print("\nCleaning up...")
        for proc in self.tcpdump_processes:
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait()
        if self.driver:
            self.driver.quit()
        sys.exit(0)
    
    def process_csv(self, csv_file):
        try:
            df = pd.read_csv(csv_file, header=None, usecols=[1])
            return df[1].tolist()
        except Exception as e:
            print(f"CSV error: {e}")
            return []
    
    def visit_website(self, domain):
        """Visit website using Selenium"""
        if not self.driver:
            return False
            
        try:
            url = f"https://{domain}"
            print(f"  Visiting {url}")
            self.driver.get(url)
            
            # Wait a bit for page to load
            time.sleep(30)
            
            # Try to wait for body element to ensure page loaded
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            print(f"  Successfully loaded {domain}")
            return True
            
        except Exception as e:
            print(f"  Website visit error for {domain}: {e}")
            return False
    
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
                    
                    # Visit website with Selenium
                    self.visit_website(domain)
                    
                    # Wait for capture
                    #time.sleep(capture_time)
                    
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