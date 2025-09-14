#!/usr/bin/env python3
"""
Comprehensive IPv6 Readiness and Performance Analyzer (v4)

This script analyzes websites from the Tranco list to provide a detailed
report on their IPv6 readiness, covering several key scenarios:
1.  Website IP Records (A and/or AAAA).
2.  Name Server (NS) Infrastructure and Glue Records (A/AAAA).
3.  Connection Preference (simulating a race between IPv4 and IPv6).
4.  IPv6 Reachability (detecting advertised but unreachable IPv6).
5.  Detailed statistics for all scenarios.
"""

import dns.resolver
import requests
import time
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Suppress noisy logs from underlying libraries
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

@dataclass
class WebsiteResult:
    """Data class to store comprehensive analysis results for a website."""
    domain: str
    traffic_rank: Optional[int]
    
    # Scenario 1: Website IP Records
    site_ip_status: str  # 'dual_stack', 'ipv4_only', 'ipv6_only', 'no_records'
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    
    # Scenario 2: NS Server Glue
    ns_servers: List[str] = field(default_factory=list)
    ns_infra_status: str = 'unknown' # 'dual_stack', 'ipv4_only', 'ipv6_only'
    
    # Scenarios 3 & 4: Connection Preference and Reachability
    ipv4_response_time: Optional[float] = None
    ipv6_response_time: Optional[float] = None
    connection_preference: str = 'none' # 'ipv6', 'ipv4', 'ipv4_only', 'ipv6_only'
    ipv6_reachability: str = 'not_applicable' # 'reachable', 'unreachable', 'not_advertised'
    
    error_message: Optional[str] = None

class IPv6ConnectivityAnalyzer:
    """Main analyzer class to perform detailed IPv6 readiness checks."""
    
    def __init__(self, timeout: int = 5, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '2001:4860:4860::8888']
        self.dns_resolver.timeout = timeout
        self.dns_resolver.lifetime = timeout

    def get_dns_records(self, domain: str, record_type: str) -> List[str]:
        """Generic function to get DNS records."""
        try:
            answers = self.dns_resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"DNS query for {domain} [{record_type}] failed: {e}")
            return []

    def test_http_connection(self, ip: str, domain: str) -> Optional[float]:
        """Tests an HTTP HEAD request to a specific IP, returning response time."""
        is_ipv6 = ':' in ip
        url = f"http://{'[' if is_ipv6 else ''}{ip}{']' if is_ipv6 else ''}"
        headers = {'Host': domain}
        try:
            start_time = time.time()
            # We don't need the body, so HEAD is efficient.
            # We also allow redirects as many sites redirect www -> non-www or http -> https
            response = requests.head(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            # Consider only successful status codes as a success
            if response.status_code < 400:
                return time.time() - start_time
        except requests.exceptions.RequestException as e:
            logger.debug(f"Connection to {ip} for host {domain} failed: {e}")
        return None

    def analyze_domain(self, domain: str, rank: int) -> WebsiteResult:
        """Performs the full analysis for a single domain."""
        logger.debug(f"Analyzing #{rank}: {domain}")
        
        # Initial DNS lookups for the website itself
        ipv4_addrs = self.get_dns_records(domain, 'A')
        ipv6_addrs = self.get_dns_records(domain, 'AAAA')

        # Scenario 1: Determine site IP status
        has_ipv4, has_ipv6 = bool(ipv4_addrs), bool(ipv6_addrs)
        if has_ipv4 and has_ipv6: site_ip_status = 'dual_stack'
        elif has_ipv4: site_ip_status = 'ipv4_only'
        elif has_ipv6: site_ip_status = 'ipv6_only'
        else: site_ip_status = 'no_records'
        
        # Scenario 2: Analyze Name Server infrastructure
        ns_hosts = [ns.rstrip('.') for ns in self.get_dns_records(domain, 'NS')]
        ns_has_ipv4_glue = False
        ns_has_ipv6_glue = False
        if ns_hosts:
            for ns in ns_hosts:
                if not ns_has_ipv4_glue and self.get_dns_records(ns, 'A'):
                    ns_has_ipv4_glue = True
                if not ns_has_ipv6_glue and self.get_dns_records(ns, 'AAAA'):
                    ns_has_ipv6_glue = True
                if ns_has_ipv4_glue and ns_has_ipv6_glue:
                    break # Optimization
        if ns_has_ipv4_glue and ns_has_ipv6_glue: ns_infra_status = 'dual_stack'
        elif ns_has_ipv4_glue: ns_infra_status = 'ipv4_only'
        elif ns_has_ipv6_glue: ns_infra_status = 'ipv6_only'
        else: ns_infra_status = 'no_glue'

        # Scenarios 3 & 4: Test connectivity and preference
        v4_time, v6_time = None, None
        preference = 'none'
        ipv6_reachability = 'not_advertised'

        if site_ip_status == 'dual_stack':
            ipv6_reachability = 'unreachable' # Assume unreachable until proven otherwise
            # Race the connections in parallel
            with ThreadPoolExecutor(max_workers=2) as executor:
                future_v4 = executor.submit(self.test_http_connection, ipv4_addrs[0], domain)
                future_v6 = executor.submit(self.test_http_connection, ipv6_addrs[0], domain)
                v4_time = future_v4.result()
                v6_time = future_v6.result()
            
            if v6_time is not None:
                ipv6_reachability = 'reachable'
            if v4_time and v6_time:
                preference = 'ipv6' if v6_time < v4_time else 'ipv4'
            elif v6_time:
                preference = 'ipv6' # v4 failed, v6 succeeded
            elif v4_time:
                preference = 'ipv4' # v6 failed, v4 succeeded

        elif site_ip_status == 'ipv4_only':
            v4_time = self.test_http_connection(ipv4_addrs[0], domain)
            preference = 'ipv4_only'
        
        elif site_ip_status == 'ipv6_only':
            v6_time = self.test_http_connection(ipv6_addrs[0], domain)
            ipv6_reachability = 'reachable' if v6_time else 'unreachable'
            preference = 'ipv6_only' if v6_time else 'none'

        return WebsiteResult(
            domain=domain, traffic_rank=rank, site_ip_status=site_ip_status,
            ipv4_addresses=ipv4_addrs, ipv6_addresses=ipv6_addrs,
            ns_servers=ns_hosts, ns_infra_status=ns_infra_status,
            ipv4_response_time=v4_time, ipv6_response_time=v6_time,
            connection_preference=preference, ipv6_reachability=ipv6_reachability,
        )

    def run_analysis(self, domains: List[Tuple[str, int]]) -> List[WebsiteResult]:
        """Analyzes a list of domains concurrently and returns the results."""
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {executor.submit(self.analyze_domain, domain, rank): domain for domain, rank in domains}
            total = len(future_to_domain)
            count = 0
            for future in as_completed(future_to_domain):
                count += 1
                try:
                    results.append(future.result())
                    if count % 50 == 0:
                        logger.info(f"Analyzed {count}/{total} domains...")
                except Exception as e:
                    logger.error(f"An exception occurred for {future_to_domain[future]}: {e}")
        return results

def load_domains_from_tranco(filepath: str, limit: int) -> List[Tuple[str, int]]:
    """Loads the top N domains from the Tranco CSV file."""
    if not os.path.exists(filepath):
        logger.error(f"FATAL: Tranco file not found at '{filepath}'. Download from https://tranco-list.eu/")
        return []
    logger.info(f"Loading top {limit} domains from {filepath}...")
    domains = []
    with open(filepath, 'r') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if i >= limit: break
            if len(row) == 2: domains.append((row[1], int(row[0])))
    logger.info(f"Loaded {len(domains)} domains.")
    return domains

def print_summary(results: List[WebsiteResult], limit: int):
    """Prints a comprehensive statistical summary of the analysis."""
    total = len(results)
    if total == 0: return

    # Counters for statistics
    stats = {
        'site_dual_stack': 0, 'site_ipv4_only': 0, 'site_ipv6_only': 0,
        'ns_dual_stack': 0, 'ns_ipv4_only': 0,
        'pref_ipv6': 0, 'pref_ipv4': 0,
        'ipv6_reachable': 0, 'ipv6_unreachable': 0
    }
    
    for r in results:
        if r.site_ip_status == 'dual_stack': stats['site_dual_stack'] += 1
        elif r.site_ip_status == 'ipv4_only': stats['site_ipv4_only'] += 1
        elif r.site_ip_status == 'ipv6_only': stats['site_ipv6_only'] += 1
        
        if r.ns_infra_status == 'dual_stack': stats['ns_dual_stack'] += 1
        elif r.ns_infra_status == 'ipv4_only': stats['ns_ipv4_only'] += 1
        
        if r.connection_preference == 'ipv6': stats['pref_ipv6'] += 1
        elif r.connection_preference == 'ipv4': stats['pref_ipv4'] += 1
        
        if r.ipv6_reachability == 'reachable': stats['ipv6_reachable'] += 1
        elif r.ipv6_reachability == 'unreachable': stats['ipv6_unreachable'] += 1

    print("\n" + "="*80)
    print(f"ANALYSIS SUMMARY FOR THE TOP {limit} WEBSITES")
    print("="*80)

    print("\n--- SCENARIO 1: WEBSITE IPV6 ADOPTION ---")
    print(f"Dual Stack (A and AAAA records): {stats['site_dual_stack']:4d} ({stats['site_dual_stack']/total*100:.1f}%)")
    print(f"IPv4-Only (No AAAA record):      {stats['site_ipv4_only']:4d} ({stats['site_ipv4_only']/total*100:.1f}%)")
    print(f"IPv6-Only (No A record):         {stats['site_ipv6_only']:4d} ({stats['site_ipv6_only']/total*100:.1f}%)")

    print("\n--- SCENARIO 2: DNS INFRASTRUCTURE (NAME SERVERS) ---")
    print(f"Sites with Dual Stack NS: {stats['ns_dual_stack']:4d} ({stats['ns_dual_stack']/total*100:.1f}%)")
    print(f"Sites with IPv4-Only NS:  {stats['ns_ipv4_only']:4d} ({stats['ns_ipv4_only']/total*100:.1f}%)")

    print("\n--- SCENARIOS 3 & 4: DUAL STACK CONNECTION PERFORMANCE ---")
    total_dual_stack = stats['site_dual_stack']
    if total_dual_stack > 0:
        print(f"Total dual stack sites tested: {total_dual_stack}")
        print(f"  - Preferred IPv6 (faster connection): {stats['pref_ipv6']:4d} ({stats['pref_ipv6']/total_dual_stack*100:.1f}%)")
        print(f"  - Preferred IPv4 (faster connection): {stats['pref_ipv4']:4d} ({stats['pref_ipv4']/total_dual_stack*100:.1f}%)")
        print(f"  - IPv6 Reachable:                     {stats['ipv6_reachable']:4d} ({stats['ipv6_reachable']/total_dual_stack*100:.1f}%)")
        print(f"  - IPv6 Unreachable (Misconfigured):   {stats['ipv6_unreachable']:4d} ({stats['ipv6_unreachable']/total_dual_stack*100:.1f}%)")
    else:
        print("No dual stack sites were found to test connection performance.")

    # Critical Findings Section
    print("\n" + "="*80)
    print("CRITICAL FINDINGS: TOP-RANKED SITES REQUIRING ATTENTION")
    print("="*80)
    
    top_ipv4_only = sorted([r for r in results if r.site_ip_status == 'ipv4_only'], key=lambda x: x.traffic_rank)[:10]
    print("\n--- Top 10 Popular IPv4-Only Websites ---")
    for r in top_ipv4_only: print(f"  Rank #{r.traffic_rank:<6} {r.domain}")

    top_ipv6_unreachable = sorted([r for r in results if r.ipv6_reachability == 'unreachable'], key=lambda x: x.traffic_rank)[:10]
    if top_ipv6_unreachable:
        print("\n--- Top 10 Popular Websites with Unreachable IPv6 (Misconfigured) ---")
        for r in top_ipv6_unreachable: print(f"  Rank #{r.traffic_rank:<6} {r.domain}")

def main():
    parser = argparse.ArgumentParser(description='Comprehensive IPv6 readiness and performance analyzer.')
    parser.add_argument('--tranco-file', type=str, default='tranco_top_1m.csv', help='Path to the Tranco top domains CSV file.')
    parser.add_argument('-n', '--limit', type=int, default=1000, help='Number of top domains to analyze from the Tranco list.')
    parser.add_argument('--timeout', type=int, default=5, help='Connection and DNS timeout in seconds.')
    parser.add_argument('--workers', type=int, default=100, help='Number of concurrent analysis workers.')
    
    args = parser.parse_args()
    
    domains = load_domains_from_tranco(args.tranco_file, args.limit)
    if not domains: return
    
    analyzer = IPv6ConnectivityAnalyzer(timeout=args.timeout, max_workers=args.workers)
    
    logger.info(f"Starting full IPv6 analysis for the top {args.limit} domains...")
    start_time = time.time()
    results = analyzer.run_analysis(domains)
    end_time = time.time()
    logger.info(f"Analysis of {len(results)} domains completed in {end_time - start_time:.2f} seconds.")
    
    # save_results(results, "full_report") # You can write a save function if needed
    print_summary(results, args.limit)

if __name__ == "__main__":
    main()
