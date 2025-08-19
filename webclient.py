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
    
    def setup_selenium(self):
        """Setup Selenium WebDriver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")  # Headless mode
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")            
            chrome_options.add_argument("--no-sandbox")  
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

            chrome_options.add_argument("--dns-server=127.0.0.1")
            chrome_options.add_argument("--disable-features=AsyncDns")
            chrome_options.add_argument("--dns-prefetch-disable")
            chrome_options.add_argument("--disable-features=SecureDns")

            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(30)
            print("Selenium WebDriver initialized")
            return driver
        except Exception as e:
            print(f"Selenium setup error: {e}")
            return None
    
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
    
    def visit_website(self, domain, capture_time=30):
        """Visit website using Selenium, fully isolated per run"""
        driver = self.setup_selenium()
        if not driver:
            return False
            
        try:
            url = f"https://{domain}"
            print(f"  Visiting {url}")
            driver.get(url)
            
            # Wait a bit for page to load
            print("Starting to wait 30 seconds for page to load...")
            time.sleep(capture_time)
            
            print(f"  Successfully loaded {domain}")
            return True
        except Exception as e:
            print(f"  Website visit error for {domain}: {e}")
            return False
        finally:
            try:
                # Clean up browser session
                driver.delete_all_cookies()
                driver.quit()
                print("  Browser cleaned up")
            except Exception:
                pass
    
    def run_tcpdump(self, interface='eth0', output_file='/tmp/dot.pcap'):
        """Start tcpdump with better error handling"""
        try:
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
    
    def monitor_domains(self, csv_files, capture_time=30, rounds=1):
        """Main monitoring function with round robin support"""
        # Pre-load all domains from CSV files
        file_domains = {}
        for csv_file in csv_files:
            if not os.path.exists(csv_file):
                print(f"File not found: {csv_file}")
                continue
            domains = self.process_csv(csv_file)
            if domains:
                filename = os.path.splitext(os.path.basename(csv_file))[0]
                file_domains[filename] = domains
        
        if not file_domains:
            print("No valid CSV files found")
            return
        
        # Round robin execution
        for round_num in range(1, rounds + 1):
            print(f"\n{'='*50}")
            print(f"Starting Round {round_num}/{rounds}")
            print(f"{'='*50}")
            
            for filename, domains in file_domains.items():
                print(f"\nProcessing {filename} (Round {round_num})")
                
                output_dir = f"./captures/{filename}/{round_num}"
                os.makedirs(output_dir, exist_ok=True)
                
                for i, domain in enumerate(domains, 1):
                    print(f"[{i}/{len(domains)}] Processing {domain}")
                    
                    pcap_file = f"{output_dir}/dot_{domain.replace('.', '_')}.pcap"
                    dump_proc = self.run_tcpdump(output_file=pcap_file)
                    
                    if dump_proc:
                        time.sleep(2)  # Let tcpdump start
                        
                        # Visit website (will auto-clean after visit)
                        self.visit_website(domain)

                        dump_proc.terminate()
                        dump_proc.wait()
                        self.tcpdump_processes.remove(dump_proc)
                        print(f"  Capture saved: {pcap_file}")
                        print("Starting 30 Seconds Timeout to act fair during measurement...")
                        time.sleep(30)
                    else:
                        print(f"  Failed to start capture for {domain}")

def main():
    csv_files = [
        "./data/categories/news.csv",
        "./data/categories/banking.csv",
        "./data/categories/streaming.csv", 
    ]
    
    monitor = DNSMonitor()
    
    try:
        monitor.monitor_domains(
            csv_files=csv_files,
            capture_time=30,
            rounds=3
        )
    except KeyboardInterrupt:
        monitor.cleanup()

if __name__ == "__main__":
    main()