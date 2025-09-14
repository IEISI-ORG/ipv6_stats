#!/usr/bin/env python3
"""
IPv4/IPv6 Website Connectivity Analyzer

This script analyzes websites to determine their IPv4/IPv6 support status:
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

def get_top_websites() -> List[Tuple[str, int, str, str]]:
    """
    Returns a curated list of 250 top websites with their ranks, categories, and regional classifications.
    Regions: Global, Americas, Europe, Asia, Africa
    """
    
    # Top 250 popular websites with regional classifications
    top_websites = [
        # Global Giants (1-20)
        ("google.com", 1, "Search", "Global"),
        ("youtube.com", 2, "Video", "Global"),
        ("facebook.com", 3, "Social Media", "Global"),
        ("twitter.com", 4, "Social Media", "Global"),
        ("instagram.com", 5, "Social Media", "Global"),
        ("wikipedia.org", 6, "Reference", "Global"),
        ("whatsapp.com", 7, "Messaging", "Global"),
        ("amazon.com", 8, "E-commerce", "Americas"),
        ("tiktok.com", 9, "Social Media", "Asia"),
        ("netflix.com", 10, "Streaming", "Americas"),
        ("microsoft.com", 11, "Technology", "Americas"),
        ("linkedin.com", 12, "Professional Network", "Global"),
        ("discord.com", 13, "Gaming/Chat", "Americas"),
        ("reddit.com", 14, "Forum", "Americas"),
        ("zoom.us", 15, "Video Conferencing", "Americas"),
        ("twitch.tv", 16, "Gaming/Streaming", "Americas"),
        ("pinterest.com", 17, "Social Media", "Americas"),
        ("snapchat.com", 18, "Social Media", "Americas"),
        ("telegram.org", 19, "Messaging", "Global"),
        ("skype.com", 20, "Video Conferencing", "Global"),
        
        # Americas - Popular Regional Sites (21-80)
        ("yahoo.com", 21, "Portal", "Americas"),
        ("ebay.com", 22, "E-commerce", "Americas"),
        ("cnn.com", 23, "News", "Americas"),
        ("paypal.com", 24, "Finance", "Americas"),
        ("adobe.com", 25, "Software", "Americas"),
        ("salesforce.com", 26, "Business Software", "Americas"),
        ("apple.com", 27, "Technology", "Americas"),
        ("github.com", 28, "Developer Platform", "Americas"),
        ("stackoverflow.com", 29, "Developer Community", "Americas"),
        ("dropbox.com", 30, "Cloud Storage", "Americas"),
        ("shopify.com", 31, "E-commerce Platform", "Americas"),
        ("wordpress.com", 32, "Blogging Platform", "Americas"),
        ("tumblr.com", 33, "Blogging Platform", "Americas"),
        ("medium.com", 34, "Blogging Platform", "Americas"),
        ("quora.com", 35, "Q&A Platform", "Americas"),
        ("imdb.com", 36, "Entertainment", "Americas"),
        ("spotify.com", 37, "Music Streaming", "Americas"),
        ("hulu.com", 38, "Streaming", "Americas"),
        ("disneyplus.com", 39, "Streaming", "Americas"),
        ("primevideo.com", 40, "Streaming", "Americas"),
        ("hbomax.com", 41, "Streaming", "Americas"),
        ("chase.com", 42, "Banking", "Americas"),
        ("bankofamerica.com", 43, "Banking", "Americas"),
        ("wellsfargo.com", 44, "Banking", "Americas"),
        ("americanexpress.com", 45, "Financial Services", "Americas"),
        ("walmart.com", 46, "Retail", "Americas"),
        ("target.com", 47, "Retail", "Americas"),
        ("bestbuy.com", 48, "Electronics", "Americas"),
        ("homedepot.com", 49, "Home Improvement", "Americas"),
        ("lowes.com", 50, "Home Improvement", "Americas"),
        ("costco.com", 51, "Retail", "Americas"),
        ("macys.com", 52, "Retail", "Americas"),
        ("etsy.com", 53, "E-commerce", "Americas"),
        ("booking.com", 54, "Travel", "Global"),
        ("expedia.com", 55, "Travel", "Americas"),
        ("airbnb.com", 56, "Travel", "Americas"),
        ("uber.com", 57, "Transportation", "Americas"),
        ("lyft.com", 58, "Transportation", "Americas"),
        ("indeed.com", 59, "Job Search", "Americas"),
        ("glassdoor.com", 60, "Job Reviews", "Americas"),
        ("yelp.com", 61, "Local Reviews", "Americas"),
        ("craigslist.org", 62, "Classifieds", "Americas"),
        ("zillow.com", 63, "Real Estate", "Americas"),
        ("realtor.com", 64, "Real Estate", "Americas"),
        ("webmd.com", 65, "Health", "Americas"),
        ("mayoclinic.org", 66, "Health", "Americas"),
        ("nytimes.com", 67, "News", "Americas"),
        ("washingtonpost.com", 68, "News", "Americas"),
        ("wsj.com", 69, "Financial News", "Americas"),
        ("foxnews.com", 70, "News", "Americas"),
        ("espn.com", 71, "Sports", "Americas"),
        ("nfl.com", 72, "Sports", "Americas"),
        ("nba.com", 73, "Sports", "Americas"),
        ("mlb.com", 74, "Sports", "Americas"),
        ("weather.com", 75, "Weather", "Americas"),
        ("accuweather.com", 76, "Weather", "Americas"),
        ("usatoday.com", 77, "News", "Americas"),
        ("msn.com", 78, "Portal", "Americas"),
        ("aol.com", 79, "Portal", "Americas"),
        ("live.com", 80, "Email", "Americas"),
        
        # Europe - Popular Regional Sites (81-140)
        ("bbc.com", 81, "News", "Europe"),
        ("bbc.co.uk", 82, "News", "Europe"),
        ("theguardian.com", 83, "News", "Europe"),
        ("dailymail.co.uk", 84, "News", "Europe"),
        ("telegraph.co.uk", 85, "News", "Europe"),
        ("reuters.com", 86, "News", "Europe"),
        ("duckduckgo.com", 87, "Search", "Europe"),
        ("yandex.ru", 88, "Search", "Europe"),
        ("mail.ru", 89, "Email", "Europe"),
        ("vk.com", 90, "Social Media", "Europe"),
        ("ok.ru", 91, "Social Media", "Europe"),
        ("livejournal.com", 92, "Blogging", "Europe"),
        ("aliexpress.com", 93, "E-commerce", "Global"),
        ("trivago.com", 94, "Travel", "Europe"),
        ("kayak.com", 95, "Travel", "Global"),
        ("skyscanner.com", 96, "Travel", "Europe"),
        ("ryanair.com", 97, "Airlines", "Europe"),
        ("easyjet.com", 98, "Airlines", "Europe"),
        ("lufthansa.com", 99, "Airlines", "Europe"),
        ("deezer.com", 100, "Music", "Europe"),
        ("soundcloud.com", 101, "Music", "Europe"),
        ("dailymotion.com", 102, "Video", "Europe"),
        ("vimeo.com", 103, "Video", "Americas"),
        ("steam.com", 104, "Gaming", "Americas"),
        ("epicgames.com", 105, "Gaming", "Americas"),
        ("ubisoft.com", 106, "Gaming", "Europe"),
        ("ea.com", 107, "Gaming", "Americas"),
        ("minecraft.net", 108, "Gaming", "Europe"),
        ("roblox.com", 109, "Gaming", "Americas"),
        ("zalando.com", 110, "E-commerce", "Europe"),
        ("otto.de", 111, "E-commerce", "Europe"),
        ("amazon.de", 112, "E-commerce", "Europe"),
        ("amazon.co.uk", 113, "E-commerce", "Europe"),
        ("amazon.fr", 114, "E-commerce", "Europe"),
        ("leboncoin.fr", 115, "Classifieds", "Europe"),
        ("marktplaats.nl", 116, "Classifieds", "Europe"),
        ("gumtree.com", 117, "Classifieds", "Europe"),
        ("olx.com", 118, "Classifieds", "Global"),
        ("allegro.pl", 119, "E-commerce", "Europe"),
        ("avito.ru", 120, "Classifieds", "Europe"),
        ("lamoda.ru", 121, "E-commerce", "Europe"),
        ("wildberries.ru", 122, "E-commerce", "Europe"),
        ("ozon.ru", 123, "E-commerce", "Europe"),
        ("sberbank.ru", 124, "Banking", "Europe"),
        ("vtb.ru", 125, "Banking", "Europe"),
        ("tinkoff.ru", 126, "Banking", "Europe"),
        ("ing.com", 127, "Banking", "Europe"),
        ("bnpparibas.com", 128, "Banking", "Europe"),
        ("deutschebank.de", 129, "Banking", "Europe"),
        ("santander.com", 130, "Banking", "Europe"),
        ("bbva.com", 131, "Banking", "Europe"),
        ("barclays.co.uk", 132, "Banking", "Europe"),
        ("hsbc.com", 133, "Banking", "Global"),
        ("creditsuisse.com", 134, "Banking", "Europe"),
        ("ubs.com", 135, "Banking", "Europe"),
        ("ing.nl", 136, "Banking", "Europe"),
        ("rabobank.com", 137, "Banking", "Europe"),
        ("carrefour.com", 138, "Retail", "Europe"),
        ("tesco.com", 139, "Retail", "Europe"),
        ("mediamarkt.com", 140, "Electronics", "Europe"),
        
        # Asia - Popular Regional Sites (141-200)
        ("baidu.com", 141, "Search", "Asia"),
        ("qq.com", 142, "Portal", "Asia"),
        ("taobao.com", 143, "E-commerce", "Asia"),
        ("tmall.com", 144, "E-commerce", "Asia"),
        ("weibo.com", 145, "Social Media", "Asia"),
        ("wechat.com", 146, "Messaging", "Asia"),
        ("douyin.com", 147, "Social Media", "Asia"),
        ("bilibili.com", 148, "Video", "Asia"),
        ("youku.com", 149, "Video", "Asia"),
        ("iqiyi.com", 150, "Video", "Asia"),
        ("163.com", 151, "Email", "Asia"),
        ("126.com", 152, "Email", "Asia"),
        ("sina.com.cn", 153, "News", "Asia"),
        ("sohu.com", 154, "Portal", "Asia"),
        ("jd.com", 155, "E-commerce", "Asia"),
        ("pinduoduo.com", 156, "E-commerce", "Asia"),
        ("meituan.com", 157, "Food Delivery", "Asia"),
        ("dianping.com", 158, "Reviews", "Asia"),
        ("ctrip.com", 159, "Travel", "Asia"),
        ("12306.cn", 160, "Transportation", "Asia"),
        ("alipay.com", 161, "Finance", "Asia"),
        ("tenpay.com", 162, "Finance", "Asia"),
        ("icbc.com.cn", 163, "Banking", "Asia"),
        ("ccb.com", 164, "Banking", "Asia"),
        ("boc.cn", 165, "Banking", "Asia"),
        ("abchina.com", 166, "Banking", "Asia"),
        ("yahoo.co.jp", 167, "Portal", "Asia"),
        ("rakuten.co.jp", 168, "E-commerce", "Asia"),
        ("amazon.co.jp", 169, "E-commerce", "Asia"),
        ("mercari.com", 170, "E-commerce", "Asia"),
        ("naver.com", 171, "Search", "Asia"),
        ("daum.net", 172, "Portal", "Asia"),
        ("kakao.com", 173, "Messaging", "Asia"),
        ("coupang.com", 174, "E-commerce", "Asia"),
        ("11st.co.kr", 175, "E-commerce", "Asia"),
        ("gmarket.co.kr", 176, "E-commerce", "Asia"),
        ("flipkart.com", 177, "E-commerce", "Asia"),
        ("amazon.in", 178, "E-commerce", "Asia"),
        ("myntra.com", 179, "E-commerce", "Asia"),
        ("paytm.com", 180, "Finance", "Asia"),
        ("phonepe.com", 181, "Finance", "Asia"),
        ("googlepay.com", 182, "Finance", "Global"),
        ("irctc.co.in", 183, "Transportation", "Asia"),
        ("makemytrip.com", 184, "Travel", "Asia"),
        ("goibibo.com", 185, "Travel", "Asia"),
        ("redbus.in", 186, "Transportation", "Asia"),
        ("ola.cab", 187, "Transportation", "Asia"),
        ("zomato.com", 188, "Food Delivery", "Asia"),
        ("swiggy.com", 189, "Food Delivery", "Asia"),
        ("hotstar.com", 190, "Streaming", "Asia"),
        ("zee5.com", 191, "Streaming", "Asia"),
        ("sonyliv.com", 192, "Streaming", "Asia"),
        ("voot.com", 193, "Streaming", "Asia"),
        ("jiosaavn.com", 194, "Music", "Asia"),
        ("gaana.com", 195, "Music", "Asia"),
        ("wynk.in", 196, "Music", "Asia"),
        ("grab.com", 197, "Transportation", "Asia"),
        ("shopee.com", 198, "E-commerce", "Asia"),
        ("lazada.com", 199, "E-commerce", "Asia"),
        ("tokopedia.com", 200, "E-commerce", "Asia"),
        
        # Africa and Middle East (201-250)
        ("jumia.com", 201, "E-commerce", "Africa"),
        ("konga.com", 202, "E-commerce", "Africa"),
        ("takealot.com", 203, "E-commerce", "Africa"),
        ("bidorbuy.co.za", 204, "E-commerce", "Africa"),
        ("gumtree.co.za", 205, "Classifieds", "Africa"),
        ("olx.co.za", 206, "Classifieds", "Africa"),
        ("property24.com", 207, "Real Estate", "Africa"),
        ("privateproperty.co.za", 208, "Real Estate", "Africa"),
        ("careers24.com", 209, "Job Search", "Africa"),
        ("pnet.co.za", 210, "Job Search", "Africa"),
        ("news24.com", 211, "News", "Africa"),
        ("iol.co.za", 212, "News", "Africa"),
        ("ewn.co.za", 213, "News", "Africa"),
        ("standardbank.co.za", 214, "Banking", "Africa"),
        ("fnb.co.za", 215, "Banking", "Africa"),
        ("absa.co.za", 216, "Banking", "Africa"),
        ("nedbank.co.za", 217, "Banking", "Africa"),
        ("capitecbank.co.za", 218, "Banking", "Africa"),
        ("mtn.com", 219, "Telecommunications", "Africa"),
        ("vodacom.co.za", 220, "Telecommunications", "Africa"),
        ("souq.com", 221, "E-commerce", "Africa"),
        ("noon.com", 222, "E-commerce", "Africa"),
        ("aljazeera.com", 223, "News", "Africa"),
        ("alarabiya.net", 224, "News", "Africa"),
        ("bbc.com/arabic", 225, "News", "Africa"),
        ("filgoal.com", 226, "Sports", "Africa"),
        ("koooora.com", 227, "Sports", "Africa"),
        ("masrawy.com", 228, "News", "Africa"),
        ("youm7.com", 229, "News", "Africa"),
        ("elwatan.com", 230, "News", "Africa"),
        ("hespress.com", 231, "News", "Africa"),
        ("menara.ma", 232, "Portal", "Africa"),
        ("orange.com", 233, "Telecommunications", "Global"),
        ("mtn.ng", 234, "Telecommunications", "Africa"),
        ("gtbank.com", 235, "Banking", "Africa"),
        ("accessbankplc.com", 236, "Banking", "Africa"),
        ("zenithbank.com", 237, "Banking", "Africa"),
        ("firstbanknigeria.com", 238, "Banking", "Africa"),
        ("uba.africa", 239, "Banking", "Africa"),
        ("punch.ng", 240, "News", "Africa"),
        ("vanguardngr.com", 241, "News", "Africa"),
        ("premiumtimesng.com", 242, "News", "Africa"),
        ("legit.ng", 243, "News", "Africa"),
        ("nairaland.com", 244, "Forum", "Africa"),
        ("linda-ikeji.blogspot.com", 245, "Blog", "Africa"),
        ("bellanaija.com", 246, "Lifestyle", "Africa"),
        ("pulse.ng", 247, "News", "Africa"),
        ("guardian.ng", 248, "News", "Africa"),
        ("techpoint.africa", 249, "Technology", "Africa"),
        ("safaricom.co.ke", 250, "Telecommunications", "Africa"),
    ]
    
    return top_websites

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
    """Print a comprehensive summary of the analysis results with regional breakdowns"""
    
    total_sites = len(results)
    ipv4_only = sum(1 for r in results if r.connectivity_status == 'ipv4_only')
    ipv6_only = sum(1 for r in results if r.connectivity_status == 'ipv6_only')
    dual_stack = sum(1 for r in results if r.connectivity_status == 'dual_stack')
    no_connectivity = sum(1 for r in results if r.connectivity_status == 'no_connectivity')
    errors = sum(1 for r in results if r.connectivity_status == 'error')
    
    print("\n" + "="*80)
    print("IPv4/IPv6 CONNECTIVITY ANALYSIS SUMMARY")
    print("="*80)
    print(f"Total websites analyzed: {total_sites}")
    print(f"IPv4 only:              {ipv4_only:3d} ({ipv4_only/total_sites*100:.1f}%)")
    print(f"IPv6 only:              {ipv6_only:3d} ({ipv6_only/total_sites*100:.1f}%)")
    print(f"Dual stack:             {dual_stack:3d} ({dual_stack/total_sites*100:.1f}%)")
    print(f"No connectivity:        {no_connectivity:3d} ({no_connectivity/total_sites*100:.1f}%)")
    print(f"Errors:                 {errors:3d} ({errors/total_sites*100:.1f}%)")
    
    # Regional breakdown
    regions = set(r.region for r in results if r.region)
    if regions:
        print("\n" + "="*80)
        print("REGIONAL ANALYSIS")
        print("="*80)
        
        for region in sorted(regions):
            regional_results = [r for r in results if r.region == region]
            if not regional_results:
                continue
                
            r_total = len(regional_results)
            r_ipv4_only = sum(1 for r in regional_results if r.connectivity_status == 'ipv4_only')
            r_ipv6_only = sum(1 for r in regional_results if r.connectivity_status == 'ipv6_only')
            r_dual_stack = sum(1 for r in regional_results if r.connectivity_status == 'dual_stack')
            
            print(f"\n{region} ({r_total} sites):")
            print(f"  IPv4 only:  {r_ipv4_only:3d} ({r_ipv4_only/r_total*100:.1f}%)")
            print(f"  IPv6 only:  {r_ipv6_only:3d} ({r_ipv6_only/r_total*100:.1f}%)")
            print(f"  Dual stack: {r_dual_stack:3d} ({r_dual_stack/r_total*100:.1f}%)")
            
            # Show top IPv4-only sites in this region
            region_ipv4_only = [r for r in regional_results if r.connectivity_status == 'ipv4_only']
            if region_ipv4_only:
                region_ipv4_only.sort(key=lambda x: x.rank if x.rank else float('inf'))
                top_ipv4_only = [r.domain for r in region_ipv4_only[:5]]
                print(f"  Top IPv4-only: {', '.join(top_ipv4_only)}")
    
    # Highlight popular IPv4-only websites globally
    ipv4_only_sites = [r for r in results if r.connectivity_status == 'ipv4_only']
    if ipv4_only_sites:
        print("\n" + "="*80)
        print("TOP POPULAR IPv4-ONLY WEBSITES (NO IPv6 SUPPORT)")
        print("="*80)
        
        # Sort by rank (lower rank = more popular)
        ipv4_only_sites.sort(key=lambda x: x.rank if x.rank else float('inf'))
        
        print(f"{'Rank':<6} {'Domain':<35} {'Category':<20} {'Region':<12} {'IPv4 Addresses'}")
        print("-" * 110)
        
        for result in ipv4_only_sites[:25]:  # Show top 25
            rank_str = str(result.rank) if result.rank else "N/A"
            category_str = result.category if result.category else "Unknown"
            region_str = result.region if result.region else "Unknown"
            ipv4_str = ', '.join(result.ipv4_addresses[:2])  # Show first 2 IPs
            if len(result.ipv4_addresses) > 2:
                ipv4_str += f" (+{len(result.ipv4_addresses)-2} more)"
            
            # Show if www. fallback was used
            domain_display = result.domain
            if result.effective_domain != result.domain:
                domain_display = f"{result.domain} → {result.effective_domain}"
            
            print(f"{rank_str:<6} {domain_display:<35} {category_str:<20} {region_str:<12} {ipv4_str}")
    
    # Category breakdown for IPv4-only sites
    if ipv4_only_sites:
        print(f"\nIPv4-ONLY SITES BY CATEGORY:")
        category_counts = {}
        for site in ipv4_only_sites:
            category = site.category or "Unknown"
            category_counts[category] = category_counts.get(category, 0) + 1
        
        for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {category}: {count}")
    
    # Show some examples of dual stack sites by region
    dual_stack_sites = [r for r in results if r.connectivity_status == 'dual_stack']
    if dual_stack_sites:
        print(f"\n" + "="*80)
        print("DUAL-STACK WEBSITES BY REGION")
        print("="*80)
        
        for region in sorted(regions):
            region_dual_stack = [r for r in dual_stack_sites if r.region == region]
            if region_dual_stack:
                region_dual_stack.sort(key=lambda x: x.rank if x.rank else float('inf'))
                examples = [r.domain for r in region_dual_stack[:8]]
                print(f"{region}: {', '.join(examples)}")
    
    # Show sites that needed www. fallback
    www_fallback_sites = [r for r in results if r.effective_domain != r.domain]
    if www_fallback_sites:
        print(f"\n" + "="*80)
        print("SITES RESOLVED WITH WWW. FALLBACK")
        print("="*80)
        print(f"Found {len(www_fallback_sites)} sites that only resolved with 'www.' prefix:")
        
        # Group by connectivity status
        fallback_by_status = {}
        for site in www_fallback_sites:
            status = site.connectivity_status
            if status not in fallback_by_status:
                fallback_by_status[status] = []
            fallback_by_status[status].append(site)
        
        for status, sites in fallback_by_status.items():
            print(f"\n{status.upper()} ({len(sites)} sites):")
            for site in sorted(sites, key=lambda x: x.rank if x.rank else float('inf'))[:10]:
                rank_str = str(site.rank) if site.rank else "N/A"
                print(f"  {rank_str:<4} {site.domain} → {site.effective_domain} ({site.region})")
            
            if len(sites) > 10:
                print(f"  ... and {len(sites) - 10} more")
    
    # IPv6 adoption rate by region
    print(f"\n" + "="*80)
    print("IPv6 ADOPTION RATE BY REGION (Dual Stack + IPv6 Only)")
    print("="*80)
    
    for region in sorted(regions):
        regional_results = [r for r in results if r.region == region]
        if not regional_results:
            continue
            
        r_total = len(regional_results)
        r_with_ipv6 = sum(1 for r in regional_results if r.has_ipv6)
        ipv6_rate = (r_with_ipv6/r_total*100) if r_total > 0 else 0
        
        print(f"{region:<12}: {r_with_ipv6:3d}/{r_total:3d} sites ({ipv6_rate:.1f}% IPv6 adoption)")

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
                    domains.append((domain, i, None, None))
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