#!/usr/bin/env python3
"""
IPv4/IPv6 Website and DNS Infrastructure Connectivity Analyzer

This script analyzes websites to determine their IPv4/IPv6 support status and 
the IPv6 readiness of their DNS infrastructure.

Website Analysis:
- IPv4 only: Has A records but no AAAA records
- IPv6 only: Has AAAA records but no A records  
- Dual stack: Has both A and AAAA records

DNS Infrastructure Analysis:
- Finds all authoritative Name Servers (NS) for the domain.
- Checks if the Name Servers themselves have IPv6 addresses.
- Verifies if the domain can be resolved by a client on an IPv6-only network.
"""

import dns.resolver
import socket
import requests
import time
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class WebsiteResult:
    """Data class to store website connectivity analysis results"""
    domain: str
    effective_domain: str
    rank: Optional[int]
    category: Optional[str]
    region: Optional[str]
    has_ipv4: bool
    has_ipv6: bool
    ipv4_addresses: List[str]
    ipv6_addresses: List[str]
    connectivity_status: str
    
    # New fields for DNS infrastructure analysis
    ns_servers: List[str]
    ns_servers_with_ipv6: List[str]
    resolvable_via_ipv6_dns: bool
    
    response_time_ipv4: Optional[float]
    response_time_ipv6: Optional[float]
    error_message: Optional[str]

class IPv6Analyzer:
    """Main analyzer class for checking IPv4/IPv6 connectivity of websites"""
    
    def __init__(self, timeout: int = 10, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        
        # Standard resolver
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = timeout
        self.dns_resolver.lifetime = timeout
        
        # Special resolver that will ONLY use public IPv6 nameservers
        self.ipv6_only_resolver = dns.resolver.Resolver()
        self.ipv6_only_resolver.nameservers = [
            '2001:4860:4860::8888',  # Google Public DNS
            '2606:4700:4700::1111'   # Cloudflare DNS
        ]
        self.ipv6_only_resolver.timeout = timeout
        self.ipv6_only_resolver.lifetime = timeout
    
    def get_dns_records(self, domain: str) -> Tuple[List[str], List[str], str]:
        """
        Get IPv4 (A) and IPv6 (AAAA) DNS records for a domain.
        If no records found for bare domain, try with 'www.' prefix.
        Returns: (ipv4_addresses, ipv6_addresses, effective_domain_used)
        """
        ipv4_addresses = []
        ipv6_addresses = []
        effective_domain = domain
        
        def try_dns_lookup(test_domain: str) -> Tuple[List[str], List[str]]:
            """Helper function to perform DNS lookup for a given domain"""
            ipv4_addrs, ipv6_addrs = [], []
            try:
                a_records = self.dns_resolver.resolve(test_domain, 'A')
                ipv4_addrs = [str(record) for record in a_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout): pass
            try:
                aaaa_records = self.dns_resolver.resolve(test_domain, 'AAAA')
                ipv6_addrs = [str(record) for record in aaaa_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout): pass
            except Exception as e:
                logger.debug(f"DNS lookup failed for {test_domain}: {e}")
            return ipv4_addrs, ipv6_addrs
        
        try:
            ipv4_addresses, ipv6_addresses = try_dns_lookup(domain)
            if not ipv4_addresses and not ipv6_addresses and not domain.startswith('www.'):
                www_domain = f"www.{domain}"
                logger.debug(f"No DNS records for {domain}, trying {www_domain}")
                www_ipv4, www_ipv6 = try_dns_lookup(www_domain)
                if www_ipv4 or www_ipv6:
                    ipv4_addresses, ipv6_addresses, effective_domain = www_ipv4, www_ipv6, www_domain
        except Exception as e:
            logger.warning(f"DNS lookup failed for {domain}: {e}")
            
        return ipv4_addresses, ipv6_addresses, effective_domain

    def analyze_ns_servers(self, domain: str) -> Tuple[List[str], List[str]]:
        """Finds NS servers and checks which ones have IPv6 addresses."""
        ns_servers = []
        ns_with_ipv6 = []
        try:
            ns_records = self.dns_resolver.resolve(domain, 'NS')
            ns_hostnames = [str(ns).rstrip('.') for ns in ns_records]
            ns_servers.extend(ns_hostnames)
            
            for ns_hostname in ns_hostnames:
                try:
                    # Check if the NS has an AAAA record
                    self.dns_resolver.resolve(ns_hostname, 'AAAA')
                    ns_with_ipv6.append(ns_hostname)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue # No IPv6 address for this NS
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            logger.warning(f"Could not retrieve NS records for {domain}: {e}")
        return ns_servers, ns_with_ipv6

    def test_ipv6_only_resolution(self, domain: str) -> bool:
        """Tests if a domain can be resolved using an IPv6-only DNS resolver."""
        try:
            # We just need any successful query to confirm it works
            self.ipv6_only_resolver.resolve(domain, 'A')
            return True
        except Exception as e:
            logger.debug(f"IPv6-only DNS resolution failed for {domain}: {e}")
            return False

    def analyze_domain(self, domain: str, rank: Optional[int] = None, category: Optional[str] = None, region: Optional[str] = None) -> WebsiteResult:
        """Analyze a single domain for IPv4/IPv6 connectivity and DNS health."""
        logger.debug(f"Analyzing {domain}")
        
        try:
            if domain.startswith(('http://', 'https://')):
                domain = urlparse(domain).netloc
            domain = domain.split('/')[0].strip()
            
            ipv4_addresses, ipv6_addresses, effective_domain = self.get_dns_records(domain)
            has_ipv4 = bool(ipv4_addresses)
            has_ipv6 = bool(ipv6_addresses)
            
            if has_ipv4 and has_ipv6: connectivity_status = "dual_stack"
            elif has_ipv4: connectivity_status = "ipv4_only"
            elif has_ipv6: connectivity_status = "ipv6_only"
            else: connectivity_status = "no_connectivity"
            
            # --- New DNS Infrastructure Analysis ---
            ns_servers, ns_servers_with_ipv6 = self.analyze_ns_servers(effective_domain)
            resolvable_via_ipv6_dns = self.test_ipv6_only_resolution(effective_domain)

            return WebsiteResult(
                domain=domain, effective_domain=effective_domain, rank=rank,
                category=category, region=region, has_ipv4=has_ipv4, has_ipv6=has_ipv6,
                ipv4_addresses=ipv4_addresses, ipv6_addresses=ipv6_addresses,
                connectivity_status=connectivity_status,
                ns_servers=ns_servers, ns_servers_with_ipv6=ns_servers_with_ipv6,
                resolvable_via_ipv6_dns=resolvable_via_ipv6_dns,
                response_time_ipv4=None, response_time_ipv6=None, error_message=None
            )
        except Exception as e:
            logger.error(f"Error analyzing {domain}: {e}")
            return WebsiteResult(
                domain=domain, effective_domain=domain, rank=rank, category=category,
                region=region, has_ipv4=False, has_ipv6=False, ipv4_addresses=[],
                ipv6_addresses=[], connectivity_status="error", ns_servers=[],
                ns_servers_with_ipv6=[], resolvable_via_ipv6_dns=False,
                response_time_ipv4=None, response_time_ipv6=None, error_message=str(e)
            )
    
    def analyze_websites(self, domains: List[Tuple[str, Optional[int], Optional[str], Optional[str]]]) -> List[WebsiteResult]:
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {executor.submit(self.analyze_domain, d, r, c, rg): (d, r, c, rg) for d, r, c, rg in domains}
            for future in as_completed(future_to_domain):
                try:
                    result = future.result()
                    results.append(result)
                    if len(results) % 10 == 0: logger.info(f"Analyzed {len(results)}/{len(domains)} websites")
                except Exception as e:
                    domain = future_to_domain[future][0]
                    logger.error(f"Failed to analyze {domain}: {e}")
        return results

def get_ipv6_test_sites() -> List[Tuple[str, int, str, str]]:
    """Returns a curated list of popular IPv6 test websites."""
    return [
        ("test-ipv6.com", 1, "Test Suite", "Global"), ("ipv6-test.com", 2, "Test Suite", "Global"),
        ("ipv6.google.com", 3, "Connectivity Check", "Global"), ("test-ipv6.cz", 4, "Test Suite", "Europe"),
        ("test-ipv6.net", 5, "Test Suite", "Global"), ("whatismyv6.com", 6, "Address Lookup", "Global"),
        ("ipv6.he.net", 7, "Connectivity Check", "Americas"), ("loopsofzen.uk", 8, "IPv6 Only", "Europe"),
        ("ipv6.is", 9, "Connectivity Check", "Europe"), ("ipv6.ch", 10, "Connectivity Check", "Europe"),
        ("ipv6-speedtest.net", 11, "Speed Test", "Global"), ("ipv6.getmyip.com", 12, "Address Lookup", "Global"),
        ("ipv4.rip", 13, "IPv6 Only", "Global"), ("ipv4.test-ipv6.com", 14, "IPv4 Only Endpoint", "Global"),
        ("ipv6.test-ipv6.com", 15, "IPv6 Only Endpoint", "Global"), ("ds.test-ipv6.com", 16, "Dual Stack Endpoint", "Global"),
        ("kame.net", 17, "Fun Check", "Asia"), ("ipv6.intel.com", 18, "Corporate", "Americas"),
        ("ipv6.facebook.com", 19, "Social Media", "Global"), ("www.v6.facebook.com", 20, "Social Media", "Global"),
        ("ipv6.github.io", 21, "Developer", "Americas"), ("ipv6.microsoft.com", 22, "Corporate", "Americas"),
        ("ipv6.com", 23, "Informational", "Global"), ("ipv6now.com.au", 24, "Consultancy", "Oceania"),
        ("ipv6.act-on.be", 25, "Consultancy", "Europe"), ("go6.net", 26, "Services", "Europe"),
        ("tunnelbroker.net", 27, "Services", "Americas"),
    ]

def save_results(results: List[WebsiteResult], filename: str = "ipv6_analysis_results"):
    csv_filename = f"{filename}.csv"
    with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'domain', 'effective_domain', 'rank', 'connectivity_status', 'has_ipv4', 'has_ipv6',
            'resolvable_via_ipv6_dns', 'ns_ipv6_support', 'ns_servers', 'ns_servers_with_ipv6',
            'ipv4_addresses', 'ipv6_addresses', 'error_message'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                'domain': r.domain, 'effective_domain': r.effective_domain, 'rank': r.rank,
                'connectivity_status': r.connectivity_status, 'has_ipv4': r.has_ipv4, 'has_ipv6': r.has_ipv6,
                'resolvable_via_ipv6_dns': r.resolvable_via_ipv6_dns,
                'ns_ipv6_support': bool(r.ns_servers_with_ipv6),
                'ns_servers': '; '.join(r.ns_servers),
                'ns_servers_with_ipv6': '; '.join(r.ns_servers_with_ipv6),
                'ipv4_addresses': '; '.join(r.ipv4_addresses),
                'ipv6_addresses': '; '.join(r.ipv6_addresses),
                'error_message': r.error_message
            })
    logger.info(f"Results saved to {csv_filename}")

def print_summary(results: List[WebsiteResult]):
    total = len(results)
    ipv4_only = sum(1 for r in results if r.connectivity_status == 'ipv4_only')
    ipv6_only = sum(1 for r in results if r.connectivity_status == 'ipv6_only')
    dual_stack = sum(1 for r in results if r.connectivity_status == 'dual_stack')
    
    print("\n" + "="*80)
    print("IPv6 TEST SITE - WEBSITE CONNECTIVITY SUMMARY")
    print("="*80)
    print(f"Total websites analyzed: {total}")
    print(f"IPv4 only:       {ipv4_only:3d} ({ipv4_only/total*100:.1f}%)")
    print(f"IPv6 only:       {ipv6_only:3d} ({ipv6_only/total*100:.1f}%)")
    print(f"Dual stack:      {dual_stack:3d} ({dual_stack/total*100:.1f}%)")

    # --- New DNS Infrastructure Summary ---
    ns_ipv6_support = sum(1 for r in results if r.ns_servers_with_ipv6)
    resolvable_ipv6 = sum(1 for r in results if r.resolvable_via_ipv6_dns)
    
    print("\n" + "="*80)
    print("DNS INFRASTRUCTURE & RESOLUTION SUMMARY")
    print("="*80)
    print(f"Sites with at least one IPv6 Name Server:  {ns_ipv6_support}/{total} ({ns_ipv6_support/total*100:.1f}%)")
    print(f"Sites resolvable via an IPv6-only DNS:     {resolvable_ipv6}/{total} ({resolvable_ipv6/total*100:.1f}%)")
    
    # --- Critical Findings ---
    unresolvable_sites = [r for r in results if not r.resolvable_via_ipv6_dns and r.connectivity_status != 'error']
    if unresolvable_sites:
        print("\n" + "-"*80)
        print("CRITICAL: SITES NOT RESOLVABLE VIA IPv6-ONLY DNS")
        print("These sites would be unreachable for clients on an IPv6-only network.")
        print("-" * 80)
        for r in unresolvable_sites:
            ns_status = "Yes" if r.ns_servers_with_ipv6 else "No"
            print(f"  - {r.domain:<25} (Status: {r.connectivity_status}, NS has IPv6: {ns_status})")

    dual_stack_no_ns_ipv6 = [r for r in results if r.connectivity_status == 'dual_stack' and not r.ns_servers_with_ipv6]
    if dual_stack_no_ns_ipv6:
        print("\n" + "-"*80)
        print("WARNING: DUAL-STACK SITES WITH IPv4-ONLY NAME SERVERS")
        print("These sites are IPv6-ready but their DNS infrastructure is not.")
        print("-" * 80)
        for r in dual_stack_no_ns_ipv6:
            print(f"  - {r.domain:<25} (NS: {', '.join(r.ns_servers[:2])})")
            
    # --- Detailed Breakdown ---
    print("\n" + "="*80)
    print("DETAILED ANALYSIS RESULTS")
    print("="*80)
    print(f"{'Domain':<25} {'Site Status':<15} {'NS IPv6?':<8} {'Resolvable on v6 DNS?'}")
    print("-" * 80)
    for r in sorted(results, key=lambda x: x.domain):
        ns_icon = "✓" if r.ns_servers_with_ipv6 else "✗"
        res_icon = "✓" if r.resolvable_via_ipv6_dns else "✗"
        print(f"{r.domain:<25} {r.connectivity_status:<15} {ns_icon:<8} {res_icon}")

def main():
    parser = argparse.ArgumentParser(description='Analyze IPv4/IPv6 connectivity and DNS infrastructure of websites.')
    parser.add_argument('--timeout', type=int, default=10, help='DNS/HTTP timeout in seconds (default: 10)')
    parser.add_argument('--workers', type=int, default=50, help='Number of concurrent workers (default: 50)')
    parser.add_argument('--output', type=str, default='ipv6_dns_analysis', help='Output filename prefix for CSV report')
    parser.add_argument('--domains-file', type=str, help='Optional file with a list of domains to analyze.')
    
    args = parser.parse_args()
    
    analyzer = IPv6Analyzer(timeout=args.timeout, max_workers=args.workers)
    
    if args.domains_file:
        with open(args.domains_file, 'r') as f:
            domains = [(line.strip(), i, "From File", "Unknown") for i, line in enumerate(f) if line.strip() and not line.startswith('#')]
        logger.info(f"Loaded {len(domains)} domains from {args.domains_file}")
    else:
        domains = get_ipv6_test_sites()
        logger.info(f"Using built-in list of {len(domains)} IPv6 test websites")
    
    logger.info("Starting IPv4/IPv6 and DNS infrastructure analysis...")
    start_time = time.time()
    
    results = analyzer.analyze_websites(domains)
    
    end_time = time.time()
    logger.info(f"Analysis completed in {end_time - start_time:.2f} seconds")
    
    save_results(results, args.output)
    print_summary(results)

if __name__ == "__main__":
    main()