#!/usr/bin/env python3
"""
IPv4/IPv6 Website Connectivity Analyzer for IPv6 Test Sites

This script analyzes websites known for IPv6 testing to determine their 
IPv4/IPv6 support status:
- IPv4 only: Has A records but no AAAA records
- IPv6 only: Has AAAA records but no A records  
- Dual stack: Has both A and AAAA records
- No connectivity: Has neither (or DNS resolution fails)

Enhanced with regional classifications and www. fallback support.
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
    effective_domain: str  # The domain that actually resolved (may include www.)
    rank: Optional[int]
    category: Optional[str]
    region: Optional[str]
    has_ipv4: bool
    has_ipv6: bool
    ipv4_addresses: List[str]
    ipv6_addresses: List[str]
    connectivity_status: str
    response_time_ipv4: Optional[float]
    response_time_ipv6: Optional[float]
    error_message: Optional[str]

class IPv6Analyzer:
    """Main analyzer class for checking IPv4/IPv6 connectivity of websites"""
    
    def __init__(self, timeout: int = 10, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = timeout
        self.dns_resolver.lifetime = timeout
    
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
            ipv4_addrs = []
            ipv6_addrs = []
            
            try:
                # Get A records (IPv4)
                try:
                    a_records = self.dns_resolver.resolve(test_domain, 'A')
                    ipv4_addrs = [str(record) for record in a_records]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    pass
                
                # Get AAAA records (IPv6)
                try:
                    aaaa_records = self.dns_resolver.resolve(test_domain, 'AAAA')
                    ipv6_addrs = [str(record) for record in aaaa_records]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    pass
                    
            except Exception as e:
                logger.debug(f"DNS lookup failed for {test_domain}: {e}")
                
            return ipv4_addrs, ipv6_addrs
        
        try:
            # First, try the original domain
            ipv4_addresses, ipv6_addresses = try_dns_lookup(domain)
            
            # If no records found and domain doesn't start with 'www.', try with 'www.' prefix
            if not ipv4_addresses and not ipv6_addresses and not domain.startswith('www.'):
                www_domain = f"www.{domain}"
                logger.debug(f"No DNS records found for {domain}, trying {www_domain}")
                
                www_ipv4, www_ipv6 = try_dns_lookup(www_domain)
                
                if www_ipv4 or www_ipv6:
                    ipv4_addresses = www_ipv4
                    ipv6_addresses = www_ipv6
                    effective_domain = www_domain
                    logger.debug(f"Found DNS records for {www_domain} instead of {domain}")
                
        except Exception as e:
            logger.warning(f"DNS lookup failed for {domain}: {e}")
            
        return ipv4_addresses, ipv6_addresses, effective_domain
    
    def test_connectivity(self, domain: str, ip_version: int) -> Optional[float]:
        """Test HTTP connectivity and measure response time"""
        try:
            if ip_version == 4:
                url = f"http://{domain}"
            else:
                url = f"http://[{domain}]"
            
            start_time = time.time()
            response = requests.head(url, timeout=self.timeout, allow_redirects=True)
            response_time = time.time() - start_time
            
            if response.status_code < 400:
                return response_time
                
        except Exception:
            pass
        
        return None
    
    def analyze_domain(self, domain: str, rank: Optional[int] = None, category: Optional[str] = None, region: Optional[str] = None) -> WebsiteResult:
        """Analyze a single domain for IPv4/IPv6 connectivity"""
        logger.debug(f"Analyzing {domain}")
        
        try:
            # Remove protocol and path if present
            if domain.startswith(('http://', 'https://')):
                domain = urlparse(domain).netloc
            domain = domain.split('/')[0].strip()
            
            # Get DNS records (with www. fallback)
            ipv4_addresses, ipv6_addresses, effective_domain = self.get_dns_records(domain)
            
            has_ipv4 = len(ipv4_addresses) > 0
            has_ipv6 = len(ipv6_addresses) > 0
            
            # Determine connectivity status
            if has_ipv4 and has_ipv6:
                connectivity_status = "dual_stack"
            elif has_ipv4 and not has_ipv6:
                connectivity_status = "ipv4_only"
            elif not has_ipv4 and has_ipv6:
                connectivity_status = "ipv6_only"
            else:
                connectivity_status = "no_connectivity"
            
            # Test response times (optional, can be slow)
            response_time_ipv4 = None
            response_time_ipv6 = None
            
            return WebsiteResult(
                domain=domain,
                effective_domain=effective_domain,
                rank=rank,
                category=category,
                region=region,
                has_ipv4=has_ipv4,
                has_ipv6=has_ipv6,
                ipv4_addresses=ipv4_addresses,
                ipv6_addresses=ipv6_addresses,
                connectivity_status=connectivity_status,
                response_time_ipv4=response_time_ipv4,
                response_time_ipv6=response_time_ipv6,
                error_message=None
            )
            
        except Exception as e:
            logger.error(f"Error analyzing {domain}: {e}")
            return WebsiteResult(
                domain=domain,
                effective_domain=domain,  # No effective domain change on error
                rank=rank,
                category=category,
                region=region,
                has_ipv4=False,
                has_ipv6=False,
                ipv4_addresses=[],
                ipv6_addresses=[],
                connectivity_status="error",
                response_time_ipv4=None,
                response_time_ipv6=None,
                error_message=str(e)
            )
    
    def analyze_websites(self, domains: List[Tuple[str, Optional[int], Optional[str], Optional[str]]]) -> List[WebsiteResult]:
        """Analyze multiple websites concurrently"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_domain = {
                executor.submit(self.analyze_domain, domain, rank, category, region): (domain, rank, category, region)
                for domain, rank, category, region in domains
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_domain):
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Log progress
                    if len(results) % 10 == 0:
                        logger.info(f"Analyzed {len(results)}/{len(domains)} websites")
                        
                except Exception as e:
                    domain_info = future_to_domain[future]
                    domain = domain_info[0] if isinstance(domain_info, tuple) else domain_info
                    logger.error(f"Failed to analyze {domain}: {e}")
        
        return results

def get_ipv6_test_sites() -> List[Tuple[str, int, str, str]]:
    """
    Returns a curated list of popular IPv6 test websites.
    The rank, category, and region fields are placeholders.
    """
    ipv6_sites = [
        # Primary IPv6 Test Sites
        ("test-ipv6.com", 1, "Test Suite", "Global"),
        ("ipv6-test.com", 2, "Test Suite", "Global"),
        ("ipv6.google.com", 3, "Connectivity Check", "Global"),
        ("test-ipv6.cz", 4, "Test Suite", "Europe"),
        ("test-ipv6.net", 5, "Test Suite", "Global"),
        ("whatismyv6.com", 6, "Address Lookup", "Global"),

        # Other well-known test endpoints
        ("ipv6.he.net", 7, "Connectivity Check", "Americas"),
        ("loopsofzen.uk", 8, "IPv6 Only", "Europe"),
        ("ipv6.is", 9, "Connectivity Check", "Europe"),
        ("ipv6.ch", 10, "Connectivity Check", "Europe"),
        ("ipv6-speedtest.net", 11, "Speed Test", "Global"),
        ("ipv6.getmyip.com", 12, "Address Lookup", "Global"),
        ("ipv4.rip", 13, "IPv6 Only", "Global"),
        
        # Sites with specific test subdomains
        ("ipv4.test-ipv6.com", 14, "IPv4 Only Endpoint", "Global"),
        ("ipv6.test-ipv6.com", 15, "IPv6 Only Endpoint", "Global"),
        ("ds.test-ipv6.com", 16, "Dual Stack Endpoint", "Global"), # ds for dual-stack

        # From various community lists
        ("kame.net", 17, "Fun Check", "Asia"),
        ("ipv6.intel.com", 18, "Corporate", "Americas"),
        ("ipv6.facebook.com", 19, "Social Media", "Global"),
        ("www.v6.facebook.com", 20, "Social Media", "Global"),
        ("ipv6.github.io", 21, "Developer", "Americas"),
        ("ipv6.microsoft.com", 22, "Corporate", "Americas"),
        ("ipv6.com", 23, "Informational", "Global"),
        ("ipv6now.com.au", 24, "Consultancy", "Oceania"),
        ("ipv6.act-on.be", 25, "Consultancy", "Europe"),
        ("go6.net", 26, "Services", "Europe"),
        ("tunnelbroker.net", 27, "Services", "Americas"),
    ]
    
    return ipv6_sites


def save_results(results: List[WebsiteResult], filename: str = "ipv6_analysis_results"):
    """Save results to both CSV and JSON formats"""
    
    # Save to CSV
    csv_filename = f"{filename}.csv"
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['domain', 'effective_domain', 'rank', 'category', 'region', 'connectivity_status', 'has_ipv4', 'has_ipv6', 
                     'ipv4_addresses', 'ipv6_addresses', 'response_time_ipv4', 'response_time_ipv6', 'error_message']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            writer.writerow({
                'domain': result.domain,
                'effective_domain': result.effective_domain,
                'rank': result.rank,
                'category': result.category,
                'region': result.region,
                'connectivity_status': result.connectivity_status,
                'has_ipv4': result.has_ipv4,
                'has_ipv6': result.has_ipv6,
                'ipv4_addresses': '; '.join(result.ipv4_addresses),
                'ipv6_addresses': '; '.join(result.ipv6_addresses),
                'response_time_ipv4': result.response_time_ipv4,
                'response_time_ipv6': result.response_time_ipv6,
                'error_message': result.error_message
            })
    
    # Save to JSON
    json_filename = f"{filename}.json"
    json_data = []
    for result in results:
        json_data.append({
            'domain': result.domain,
            'effective_domain': result.effective_domain,
            'rank': result.rank,
            'category': result.category,
            'region': result.region,
            'connectivity_status': result.connectivity_status,
            'has_ipv4': result.has_ipv4,
            'has_ipv6': result.has_ipv6,
            'ipv4_addresses': result.ipv4_addresses,
            'ipv6_addresses': result.ipv6_addresses,
            'response_time_ipv4': result.response_time_ipv4,
            'response_time_ipv6': result.response_time_ipv6,
            'error_message': result.error_message
        })
    
    with open(json_filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(json_data, jsonfile, indent=2, ensure_ascii=False)
    
    logger.info(f"Results saved to {csv_filename} and {json_filename}")

def print_summary(results: List[WebsiteResult]):
    """Print a comprehensive summary of the analysis results with a focus on IPv6-Only sites"""
    
    total_sites = len(results)
    ipv4_only = sum(1 for r in results if r.connectivity_status == 'ipv4_only')
    ipv6_only = sum(1 for r in results if r.connectivity_status == 'ipv6_only')
    dual_stack = sum(1 for r in results if r.connectivity_status == 'dual_stack')
    no_connectivity = sum(1 for r in results if r.connectivity_status == 'no_connectivity')
    errors = sum(1 for r in results if r.connectivity_status == 'error')
    
    print("\n" + "="*80)
    print("IPv6 TEST SITE CONNECTIVITY ANALYSIS")
    print("="*80)
    print(f"Total websites analyzed: {total_sites}")
    print(f"IPv4 only:              {ipv4_only:3d} ({ipv4_only/total_sites*100:.1f}%)")
    print(f"IPv6 only:              {ipv6_only:3d} ({ipv6_only/total_sites*100:.1f}%)")
    print(f"Dual stack:             {dual_stack:3d} ({dual_stack/total_sites*100:.1f}%)")
    print(f"No connectivity:        {no_connectivity:3d} ({no_connectivity/total_sites*100:.1f}%)")
    print(f"Errors:                 {errors:3d} ({errors/total_sites*100:.1f}%)")
    
    # Highlight IPv6-Only websites, as requested
    ipv6_only_sites = [r for r in results if r.connectivity_status == 'ipv6_only']
    if ipv6_only_sites:
        print("\n" + "="*80)
        print("FOUND IPv6-ONLY WEBSITES (NO IPv4 SUPPORT)")
        print("="*80)
        
        ipv6_only_sites.sort(key=lambda x: x.rank if x.rank else float('inf'))
        
        print(f"{'Rank':<6} {'Domain':<35} {'Category':<25} {'IPv6 Addresses'}")
        print("-" * 110)
        
        for result in ipv6_only_sites:
            rank_str = str(result.rank) if result.rank else "N/A"
            category_str = result.category if result.category else "Unknown"
            ipv6_str = ', '.join(result.ipv6_addresses[:2])
            if len(result.ipv6_addresses) > 2:
                ipv6_str += f" (+{len(result.ipv6_addresses)-2} more)"
            
            print(f"{rank_str:<6} {result.domain:<35} {category_str:<25} {ipv6_str}")

    # Highlight popular IPv4-only websites
    ipv4_only_sites = [r for r in results if r.connectivity_status == 'ipv4_only']
    if ipv4_only_sites:
        print("\n" + "="*80)
        print("IPv4-ONLY WEBSITES (NO IPv6 SUPPORT)")
        print("="*80)
        
        ipv4_only_sites.sort(key=lambda x: x.rank if x.rank else float('inf'))
        
        print(f"{'Rank':<6} {'Domain':<35} {'Category':<25} {'IPv4 Addresses'}")
        print("-" * 110)
        
        for result in ipv4_only_sites:
            rank_str = str(result.rank) if result.rank else "N/A"
            category_str = result.category if result.category else "Unknown"
            ipv4_str = ', '.join(result.ipv4_addresses[:2])
            if len(result.ipv4_addresses) > 2:
                ipv4_str += f" (+{len(result.ipv4_addresses)-2} more)"

            print(f"{rank_str:<6} {result.domain:<35} {category_str:<25} {ipv4_str}")

    # Show some examples of dual stack sites
    dual_stack_sites = [r for r in results if r.connectivity_status == 'dual_stack']
    if dual_stack_sites:
        print(f"\n" + "="*80)
        print("DUAL-STACK WEBSITES (SUPPORTING BOTH IPv4 AND IPv6)")
        print("="*80)
        
        dual_stack_sites.sort(key=lambda x: x.rank if x.rank else float('inf'))
        for result in dual_stack_sites[:15]: # Show top 15
             rank_str = str(result.rank) if result.rank else "N/A"
             print(f"  {rank_str:<4} {result.domain}")

def main():
    parser = argparse.ArgumentParser(description='Analyze IPv4/IPv6 connectivity of popular IPv6 test websites')
    parser.add_argument('--timeout', type=int, default=10, help='DNS/HTTP timeout in seconds (default: 10)')
    parser.add_argument('--workers', type=int, default=50, help='Number of concurrent workers (default: 50)')
    parser.add_argument('--output', type=str, default='ipv6_test_site_analysis', help='Output filename prefix')
    parser.add_argument('--domains-file', type=str, help='File containing list of domains to analyze (one per line)')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = IPv6Analyzer(timeout=args.timeout, max_workers=args.workers)
    
    # Get list of domains to analyze
    if args.domains_file:
        # Load domains from file
        domains = []
        with open(args.domains_file, 'r') as f:
            for i, line in enumerate(f, 1):
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    domains.append((domain, i, "From File", "Unknown"))
        logger.info(f"Loaded {len(domains)} domains from {args.domains_file}")
    else:
        # Use built-in list of IPv6 test websites
        domains = get_ipv6_test_sites()
        logger.info(f"Using built-in list of {len(domains)} IPv6 test websites")
    
    logger.info("Starting IPv4/IPv6 connectivity analysis for IPv6 test sites...")
    start_time = time.time()
    
    # Analyze all domains
    results = analyzer.analyze_websites(domains)
    
    end_time = time.time()
    logger.info(f"Analysis completed in {end_time - start_time:.2f} seconds")
    
    # Save and display results
    save_results(results, args.output)
    print_summary(results)

if __name__ == "__main__":
    main()