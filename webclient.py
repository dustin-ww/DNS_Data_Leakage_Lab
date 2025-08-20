#!/usr/bin/env python3
import dns.message
import dns.query
import dns.rdatatype
import time
import pandas as pd
import subprocess
import os
import signal
import logging
import sys
from selenium import webdriver
from datetime import datetime
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/dns/dns-webclient-measure.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class DNSMonitor:
    def __init__(self):
        self.tcpdump_processes = []
        self.driver = None
        signal.signal(signal.SIGINT, self.cleanup)

        self.log_file = "./visits_log.txt"
        self.init_log_file()

    def init_log_file(self):
        """Initialize log file with header"""
        try:
            with open(self.log_file, 'w') as f:
                f.write(f"DNS Monitor Visit Log - Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n")
        except Exception as e:
            logging.error(f"Log file init error: {e}")
    
    def log_visit(self, domain, status, round_num, category, error_msg=None):
        """Log website visit details"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            status_str = "SUCCESS" if status else "FAILED"
            
            log_entry = f"[{timestamp}] Round {round_num} | {category} | {domain} | {status_str}"
            if error_msg:
                log_entry += f" | Error: {error_msg}"
            log_entry += "\n"
            
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
                
        except Exception as e:
            logging.error(f"Logging error: {e}")
    
    
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
            logging.info("Selenium WebDriver initialized")
            return driver
        except Exception as e:
            logging.error(f"Selenium setup error: {e}")
            return None
    
    def cleanup(self, signum=None, frame=None):
        """Clean up tcpdump processes and selenium on exit"""
        logging.info("Cleaning up DNSMonitor resources")
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
            logging.error(f"CSV error: {e}")
            return []
    
    def visit_website(self, domain, capture_time=30, round_num=1, category="unknown"):
        """Visit website using Selenium, fully isolated per run"""
        driver = self.setup_selenium()
        if not driver:
            return False
            
        try:
            url = f"https://{domain}"
            logging.info(f"  Visiting {url}")
            driver.get(url)
            
            # Wait a bit for page to load
            logging.info("Starting to wait 30 seconds for page to load...")
            time.sleep(capture_time)
            
            logging.info(f"  Successfully loaded {domain}")
            self.log_visit(domain, True, round_num, category)
            return True
        except Exception as e:
            logging.error(f"  Website visit error for {domain}: {e}")
            self.log_visit(domain, False, round_num, category, str(e))
            return False
        finally:
            try:
                # Clean up browser session
                driver.delete_all_cookies()
                driver.quit()
                logging.info("  Browser cleaned up")
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
            logging.info(f"Started capture: {output_file}")
            return process
            
        except Exception as e:
            logging.error(f"TCPDump error: {e}")
            return None
    
    def monitor_domains(self, csv_files, capture_time=30, rounds=1):
        """Main monitoring function with round robin support"""
        # Pre-load all domains from CSV files
        file_domains = {}
        for csv_file in csv_files:
            if not os.path.exists(csv_file):
                logging.warning(f"File not found: {csv_file}")
                continue
            domains = self.process_csv(csv_file)
            if domains:
                filename = os.path.splitext(os.path.basename(csv_file))[0]
                file_domains[filename] = domains
        
        if not file_domains:
            logging.error("No valid CSV files found")
            return
        
        # Round robin execution
        for round_num in range(1, rounds + 1):
            logging.info(f"\n{'='*50}")
            logging.info(f"Starting Round {round_num}/{rounds}")
            logging.info(f"{'='*50}")
            
            for filename, domains in file_domains.items():
                logging.info(f"\nProcessing {filename} (Round {round_num})")
                
                output_dir = f"./captures/{filename}/{round_num}"
                os.makedirs(output_dir, exist_ok=True)
                
                for i, domain in enumerate(domains, 1):
                    logging.info(f"[{i}/{len(domains)}] Processing {domain}")
                    
                    pcap_file = f"{output_dir}/dot_{domain.replace('.', '_')}.pcap"
                    dump_proc = self.run_tcpdump(output_file=pcap_file)
                    
                    if dump_proc:
                        time.sleep(2)  # Let tcpdump start
                        
                        # Visit website (will auto-clean after visit)
                        self.visit_website(domain, capture_time, round_num, filename)

                        dump_proc.terminate()
                        dump_proc.wait()
                        self.tcpdump_processes.remove(dump_proc)
                        logging.info(f"  Capture saved: {pcap_file}")
                        logging.info("Starting 10 Seconds Timeout to act fair during measurement...")
                        time.sleep(10)
                    else:
                        logging.error(f"  Failed to start capture for {domain}")

def main():
    csv_files = [
        "./data/categories/news.csv",
        "./data/categories/casino.csv",
        "./data/categories/streaming.csv", 
        "./data/categories/top.csv"
    ]
    
    monitor = DNSMonitor()
    
    try:
        monitor.monitor_domains(
            csv_files=csv_files,
            capture_time=30,
            rounds=10
        )
    except KeyboardInterrupt:
        monitor.cleanup()

if __name__ == "__main__":
    main()