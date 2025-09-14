#!/usr/bin/env python3
"""
IPv4/IPv6 Website Connectivity Analyzer

This script analyzes websites to determine their IPv4/IPv6 support status:
- IPv4 only: Has A records but no AAAA records
- IPv6 only: Has AAAA records but no A records  
- Dual stack: Has both A and AAAA records
- No connectivity: Has neither (or DNS resolution fails)

Data sources included:
- Top 1000 websites from various popularity rankings
- Special focus on identifying popular IPv4-only websites
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
    rank: Optional[int]
    category: Optional[str]
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
    
    def get_dns_records(self, domain: str) -> Tuple[List[str], List[str]]:
        """Get IPv4 (A) and IPv6 (AAAA) DNS records for a domain"""
        ipv4_addresses = []
        ipv6_addresses = []
        
        try:
            # Get A records (IPv4)
            try:
                a_records = self.dns_resolver.resolve(domain, 'A')
                ipv4_addresses = [str(record) for record in a_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            
            # Get AAAA records (IPv6)
            try:
                aaaa_records = self.dns_resolver.resolve(domain, 'AAAA')
                ipv6_addresses = [str(record) for record in aaaa_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
                
        except Exception as e:
            logger.warning(f"DNS lookup failed for {domain}: {e}")
            
        return ipv4_addresses, ipv6_addresses
    
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
    
    def analyze_domain(self, domain: str, rank: Optional[int] = None, category: Optional[str] = None) -> WebsiteResult:
        """Analyze a single domain for IPv4/IPv6 connectivity"""
        logger.debug(f"Analyzing {domain}")
        
        try:
            # Remove protocol and path if present
            if domain.startswith(('http://', 'https://')):
                domain = urlparse(domain).netloc
            domain = domain.split('/')[0].strip()
            
            # Get DNS records
            ipv4_addresses, ipv6_addresses = self.get_dns_records(domain)
            
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
                rank=rank,
                category=category,
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
                rank=rank,
                category=category,
                has_ipv4=False,
                has_ipv6=False,
                ipv4_addresses=[],
                ipv6_addresses=[],
                connectivity_status="error",
                response_time_ipv4=None,
                response_time_ipv6=None,
                error_message=str(e)
            )
    
    def analyze_websites(self, domains: List[Tuple[str, Optional[int], Optional[str]]]) -> List[WebsiteResult]:
        """Analyze multiple websites concurrently"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_domain = {
                executor.submit(self.analyze_domain, domain, rank, category): domain
                for domain, rank, category in domains
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
                    domain = future_to_domain[future]
                    logger.error(f"Failed to analyze {domain}: {e}")
        
        return results

def get_top_websites() -> List[Tuple[str, int, str]]:
    """
    Returns a curated list of top websites with their approximate ranks.
    In a real implementation, you might fetch this from:
    - Alexa Top Sites (discontinued but archives exist)
    - Tranco list (https://tranco-list.eu/)
    - Cisco Umbrella 1 Million
    - Chrome User Experience Report
    - Or web scrape from various ranking sites
    """
    
    # Top 100 popular websites (manually curated list)
    top_websites = [
        ("google.com", 1, "Search"),
        ("youtube.com", 2, "Video"),
        ("facebook.com", 3, "Social Media"),
        ("twitter.com", 4, "Social Media"),
        ("instagram.com", 5, "Social Media"),
        ("baidu.com", 6, "Search"),
        ("wikipedia.org", 7, "Reference"),
        ("yandex.ru", 8, "Search"),
        ("yahoo.com", 9, "Portal"),
        ("whatsapp.com", 10, "Messaging"),
        ("amazon.com", 11, "E-commerce"),
        ("tiktok.com", 12, "Social Media"),
        ("live.com", 13, "Email"),
        ("reddit.com", 14, "Forum"),
        ("netflix.com", 15, "Streaming"),
        ("microsoft.com", 16, "Technology"),
        ("office.com", 17, "Productivity"),
        ("zoom.us", 18, "Video Conferencing"),
        ("discord.com", 19, "Gaming/Chat"),
        ("twitch.tv", 20, "Gaming/Streaming"),
        ("linkedin.com", 21, "Professional Network"),
        ("news.google.com", 22, "News"),
        ("bing.com", 23, "Search"),
        ("duckduckgo.com", 24, "Search"),
        ("pinterest.com", 25, "Social Media"),
        ("ebay.com", 26, "E-commerce"),
        ("cnn.com", 27, "News"),
        ("bbc.com", 28, "News"),
        ("stackoverflow.com", 29, "Developer Community"),
        ("github.com", 30, "Developer Platform"),
        ("apple.com", 31, "Technology"),
        ("adobe.com", 32, "Software"),
        ("paypal.com", 33, "Finance"),
        ("salesforce.com", 34, "Business Software"),
        ("dropbox.com", 35, "Cloud Storage"),
        ("shopify.com", 36, "E-commerce Platform"),
        ("wordpress.com", 37, "Blogging Platform"),
        ("tumblr.com", 38, "Blogging Platform"),
        ("medium.com", 39, "Blogging Platform"),
        ("quora.com", 40, "Q&A Platform"),
        ("imdb.com", 41, "Entertainment"),
        ("spotify.com", 42, "Music Streaming"),
        ("soundcloud.com", 43, "Music Platform"),
        ("vimeo.com", 44, "Video Platform"),
        ("dailymotion.com", 45, "Video Platform"),
        ("twitch.tv", 46, "Live Streaming"),
        ("hulu.com", 47, "Streaming"),
        ("disneyplus.com", 48, "Streaming"),
        ("primevideo.com", 49, "Streaming"),
        ("hbomax.com", 50, "Streaming"),
        # Adding more domains for comprehensive analysis
        ("cloudflare.com", 51, "CDN/Security"),
        ("godaddy.com", 52, "Domain/Hosting"),
        ("namecheap.com", 53, "Domain/Hosting"),
        ("digitalocean.com", 54, "Cloud Hosting"),
        ("aws.amazon.com", 55, "Cloud Platform"),
        ("azure.microsoft.com", 56, "Cloud Platform"),
        ("cloud.google.com", 57, "Cloud Platform"),
        ("heroku.com", 58, "Cloud Platform"),
        ("netlify.com", 59, "Web Development"),
        ("vercel.com", 60, "Web Development"),
        # Financial services
        ("chase.com", 61, "Banking"),
        ("bankofamerica.com", 62, "Banking"),
        ("wellsfargo.com", 63, "Banking"),
        ("citibank.com", 64, "Banking"),
        ("americanexpress.com", 65, "Financial Services"),
        # E-commerce
        ("etsy.com", 66, "E-commerce"),
        ("walmart.com", 67, "Retail"),
        ("target.com", 68, "Retail"),
        ("bestbuy.com", 69, "Electronics"),
        ("homedepot.com", 70, "Home Improvement"),
        # Travel
        ("booking.com", 71, "Travel"),
        ("expedia.com", 72, "Travel"),
        ("airbnb.com", 73, "Travel"),
        ("tripadvisor.com", 74, "Travel"),
        ("uber.com", 75, "Transportation"),
        # Gaming
        ("steam.com", 76, "Gaming"),
        ("epicgames.com", 77, "Gaming"),
        ("roblox.com", 78, "Gaming"),
        ("minecraft.net", 79, "Gaming"),
        ("ea.com", 80, "Gaming"),
        # News and Media
        ("nytimes.com", 81, "News"),
        ("washingtonpost.com", 82, "News"),
        ("theguardian.com", 83, "News"),
        ("reuters.com", 84, "News"),
        ("bloomberg.com", 85, "Financial News"),
        # Education
        ("coursera.org", 86, "Education"),
        ("edx.org", 87, "Education"),
        ("khanacademy.org", 88, "Education"),
        ("udemy.com", 89, "Education"),
        ("duolingo.com", 90, "Language Learning"),
        # Additional popular sites
        ("weather.com", 91, "Weather"),
        ("indeed.com", 92, "Job Search"),
        ("glassdoor.com", 93, "Job Reviews"),
        ("yelp.com", 94, "Local Reviews"),
        ("craigslist.org", 95, "Classifieds"),
        ("zillow.com", 96, "Real Estate"),
        ("realtor.com", 97, "Real Estate"),
        ("webmd.com", 98, "Health"),
        ("mayoclinic.org", 99, "Health"),
        ("healthline.com", 100, "Health"),
    ]
    
    return top_websites

def save_results(results: List[WebsiteResult], filename: str = "ipv6_analysis_results"):
    """Save results to both CSV and JSON formats"""
    
    # Save to CSV
    csv_filename = f"{filename}.csv"
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['domain', 'rank', 'category', 'connectivity_status', 'has_ipv4', 'has_ipv6', 
                     'ipv4_addresses', 'ipv6_addresses', 'response_time_ipv4', 'response_time_ipv6', 'error_message']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            writer.writerow({
                'domain': result.domain,
                'rank': result.rank,
                'category': result.category,
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
            'rank': result.rank,
            'category': result.category,
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
    """Print a summary of the analysis results"""
    
    total_sites = len(results)
    ipv4_only = sum(1 for r in results if r.connectivity_status == 'ipv4_only')
    ipv6_only = sum(1 for r in results if r.connectivity_status == 'ipv6_only')
    dual_stack = sum(1 for r in results if r.connectivity_status == 'dual_stack')
    no_connectivity = sum(1 for r in results if r.connectivity_status == 'no_connectivity')
    errors = sum(1 for r in results if r.connectivity_status == 'error')
    
    print("\n" + "="*60)
    print("IPv4/IPv6 CONNECTIVITY ANALYSIS SUMMARY")
    print("="*60)
    print(f"Total websites analyzed: {total_sites}")
    print(f"IPv4 only:              {ipv4_only:3d} ({ipv4_only/total_sites*100:.1f}%)")
    print(f"IPv6 only:              {ipv6_only:3d} ({ipv6_only/total_sites*100:.1f}%)")
    print(f"Dual stack:             {dual_stack:3d} ({dual_stack/total_sites*100:.1f}%)")
    print(f"No connectivity:        {no_connectivity:3d} ({no_connectivity/total_sites*100:.1f}%)")
    print(f"Errors:                 {errors:3d} ({errors/total_sites*100:.1f}%)")
    
    # Highlight popular IPv4-only websites
    ipv4_only_sites = [r for r in results if r.connectivity_status == 'ipv4_only']
    if ipv4_only_sites:
        print("\n" + "="*60)
        print("POPULAR IPv4-ONLY WEBSITES (NO IPv6 SUPPORT)")
        print("="*60)
        
        # Sort by rank (lower rank = more popular)
        ipv4_only_sites.sort(key=lambda x: x.rank if x.rank else float('inf'))
        
        print(f"{'Rank':<6} {'Domain':<25} {'Category':<20} {'IPv4 Addresses'}")
        print("-" * 80)
        
        for result in ipv4_only_sites[:20]:  # Show top 20
            rank_str = str(result.rank) if result.rank else "N/A"
            category_str = result.category if result.category else "Unknown"
            ipv4_str = ', '.join(result.ipv4_addresses[:2])  # Show first 2 IPs
            if len(result.ipv4_addresses) > 2:
                ipv4_str += f" (+{len(result.ipv4_addresses)-2} more)"
            
            print(f"{rank_str:<6} {result.domain:<25} {category_str:<20} {ipv4_str}")
    
    # Show some examples of dual stack sites
    dual_stack_sites = [r for r in results if r.connectivity_status == 'dual_stack']
    if dual_stack_sites:
        print(f"\nExample dual-stack websites: {', '.join([r.domain for r in dual_stack_sites[:10]])}")

def main():
    parser = argparse.ArgumentParser(description='Analyze IPv4/IPv6 connectivity of popular websites')
    parser.add_argument('--timeout', type=int, default=10, help='DNS/HTTP timeout in seconds (default: 10)')
    parser.add_argument('--workers', type=int, default=50, help='Number of concurrent workers (default: 50)')
    parser.add_argument('--output', type=str, default='ipv6_analysis_results', help='Output filename prefix')
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
                    domains.append((domain, i, None))
        logger.info(f"Loaded {len(domains)} domains from {args.domains_file}")
    else:
        # Use built-in list of popular websites
        domains = get_top_websites()
        logger.info(f"Using built-in list of {len(domains)} popular websites")
    
    logger.info("Starting IPv4/IPv6 connectivity analysis...")
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
