#!/usr/bin/env python3
import dns.message
import dns.query
import dns.rdatatype
import time
import pandas as pd
import subprocess

def process_tranco_csv(csv_file, limit=100):
    try:
        df = pd.read_csv(csv_file, header=None, usecols=[1], nrows=limit)
        return df[1].tolist()
    except Exception as e:
        print(f"CSV error: {e}")
        return []

def resolve_dot(domain, server='9.9.9.9', port=853):
    """DNS over TLS query"""
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A)
        response = dns.query.tls(query, server, port=port, timeout=5)
        ips = []
        if response.answer:
            for ans in response.answer:
                for item in ans.items:
                    ips.append(item.to_text())
        return ips
    except Exception as e:
        print(f"DoT error for {domain}: {e}")
        return []
    
def run_tcpdump(interface='eth0', output_file='/opt/captures/dot.pcap'):
    """Run tcpdump to capture DNS over TLS traffic"""
    try:
        cmd = ['tcpdump', '-i', interface, '-w', output_file, '-s', '0', '-U', 'port', '853']
        process = subprocess.Popen(cmd)
        print(f"TCPDump started on {interface}, capturing to {output_file}")
        return process
    except Exception as e:
        print(f"TCPDump error: {e}")

if __name__ == "__main__":
    # Path to the recent tranco top list
    tranco_file = "./data/tranco/tranco_top_1m.csv"
    domains = process_tranco_csv(tranco_file, 100)

    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] Resolving {domain} via DoT")
        dump_proc = run_tcpdump(output_file=f"./test/dot_{domain}.pcap")
        
        ips = resolve_dot(domain)
        print(f"{domain} -> {ips}")
        time.sleep(30)
        print(f"Stopping tcpdump for {domain}, output saved to /opt/captures/dot_{domain}.pcap")
        dump_proc.terminate()
        dump_proc.wait()
