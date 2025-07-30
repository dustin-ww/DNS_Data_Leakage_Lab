#!/usr/bin/env python3
import dns.message
import dns.query
import dns.rdatatype
import time
import pandas as pd

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

if __name__ == "__main__":
    # Path to the recent tranco top list
    tranco_file = "./data/tranco_july-25-1m.csv/top-1m.csv"
    domains = process_tranco_csv(tranco_file, 100)

    if not domains:
        print("No domains found. Using sample domains:")
        domains = ['google.com', 'youtube.com', 'facebook.com']

    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] Resolving {domain} via DoT")
        ips = resolve_dot(domain)
        print(f"{domain} -> {ips}")
        time.sleep(30)
