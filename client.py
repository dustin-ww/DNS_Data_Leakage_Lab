#!/usr/bin/env python3
"""
Minimales Selenium Script mit DoH/DoT
pip install selenium requests
"""

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

class MinimalDoHBrowser:
    def __init__(self):
        self.doh_url = 'https://1.1.1.1/dns-query'
        self.driver = None
    
    def resolve_doh(self, domain):
        """DNS über HTTPS auflösen"""
        try:
            response = requests.get(
                self.doh_url,
                headers={'Accept': 'application/dns-json'},
                params={'name': domain, 'type': 'A'},
                timeout=5
            )
            data = response.json()
            if 'Answer' in data:
                return [answer['data'] for answer in data['Answer']]
            return []
        except Exception as e:
            print(f"DoH Fehler: {e}")
            return []
    
    def setup_browser(self):
        """Chrome mit DoH starten"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--enable-features=DnsOverHttps')
        options.add_argument('--force-dns-over-https-template=https://1.1.1.1/dns-query')
        
        self.driver = webdriver.Chrome(options=options)
        return self.driver
    
    def visit(self, url):
        """Website besuchen"""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # DNS vorab auflösen
        ips = self.resolve_doh(domain)
        print(f"{domain} -> {ips}")
        
        # Website besuchen
        self.driver.get(url)
        print(f"Titel: {self.driver.title}")
        return self.driver.title
    
    def close(self):
        if self.driver:
            self.driver.quit()

# Tranco CSV verarbeiten
def process_tranco_csv(csv_file, limit=100):
    """Erste N Domains aus Tranco CSV laden"""
    import csv
    domains = []
    
    try:
        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i >= limit:
                    break
                if len(row) >= 2:  # Tranco Format: rank,domain
                    domains.append(row[1])
    except Exception as e:
        print(f"CSV Fehler: {e}")
    
    return domains

# Verwendung
if __name__ == "__main__":
    # Tranco CSV Datei angeben
    tranco_file = "tranco_list.csv"  # Pfad zu deiner Tranco CSV
    
    # Erste 100 Domains laden
    domains = process_tranco_csv(tranco_file, 100)
    print(f"Geladene Domains: {len(domains)}")
    
    if not domains:
        print("Keine Domains gefunden. Verwende Beispiel-Domains:")
        domains = ['google.com', 'youtube.com', 'facebook.com']
    
    browser = MinimalDoHBrowser()
    browser.setup_browser()
    
    results = []
    
    try:
        for i, domain in enumerate(domains, 1):
            print(f"\n[{i}/{len(domains)}] Teste: {domain}")
            try:
                url = f"https://{domain}"
                title = browser.visit(url)
                results.append({'domain': domain, 'title': title, 'status': 'success'})
            except Exception as e:
                print(f"Fehler bei {domain}: {e}")
                results.append({'domain': domain, 'title': None, 'status': 'error'})
    
    finally:
        browser.close()
        
        # Ergebnisse ausgeben
        print(f"\n=== Zusammenfassung ===")
        successful = sum(1 for r in results if r['status'] == 'success')
        print(f"Erfolgreich: {successful}/{len(results)}")
        
        # Erste 10 Ergebnisse anzeigen
        for result in results[:10]:
            status = "✓" if result['status'] == 'success' else "✗"
            print(f"{status} {result['domain']}: {result['title']}")