import csv
import socket
import time
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
INPUT_FILE = 'cloudflare-radar_top-100-domains_au_20251116-20251123.csv'
OUTPUT_FILE = 'ipv6_analysis_report.csv'
MAX_THREADS = 20
TIMEOUT = 3.0  # Seconds for socket connection timeout

class DomainResult:
    def __init__(self, domain, rank):
        self.domain = domain
        self.rank = rank
        self.has_a = False
        self.has_aaaa = False
        self.ns_has_aaaa = False
        self.ipv4_rtt = None
        self.ipv6_rtt = None
        self.ipv6_reachable = False
        self.preference = "N/A"
        self.error = None

def get_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []

def check_ns_ipv6(domain):
    """Checks if any authoritative Name Server for the domain has an AAAA record."""
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            target = ns.target.to_text()
            # Check if this NS host has an AAAA record
            if get_dns_records(target, 'AAAA'):
                return True
        return False
    except Exception:
        return False

def test_connection(address, port=443):
    """
    Attempts a TCP connection to measure RTT and reachability.
    Returns (success_bool, rtt_ms).
    """
    start_time = time.time()
    s = None
    try:
        # Determine address family based on syntax
        if ":" in address:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET
            
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((address, port))
        end_time = time.time()
        rtt = (end_time - start_time) * 1000 # convert to ms
        return True, rtt
    except Exception:
        return False, None
    finally:
        if s:
            s.close()

def analyze_domain(row):
    # Handle different CSV structures, assuming rank/domain are first two or labeled
    try:
        rank = row['rank']
        domain = row['domain']
    except KeyError:
        # Fallback for headerless or different headers
        rank = list(row.values())[0]
        domain = list(row.values())[1]

    result = DomainResult(domain, rank)

    try:
        # 1. DNS Records
        a_records = get_dns_records(domain, 'A')
        aaaa_records = get_dns_records(domain, 'AAAA')

        result.has_a = len(a_records) > 0
        result.has_aaaa = len(aaaa_records) > 0

        # 2. Name Server Infrastructure (Glue/NS check)
        result.ns_has_aaaa = check_ns_ipv6(domain)

        # 3 & 4. Connection Preference & Reachability
        # Test IPv4
        if result.has_a:
            v4_success, v4_rtt = test_connection(a_records[0])
            if v4_success:
                result.ipv4_rtt = round(v4_rtt, 2)

        # Test IPv6
        if result.has_aaaa:
            v6_success, v6_rtt = test_connection(aaaa_records[0])
            if v6_success:
                result.ipv6_reachable = True
                result.ipv6_rtt = round(v6_rtt, 2)

        # Determine Preference
        if result.ipv4_rtt is not None and result.ipv6_rtt is not None:
            # Simple simulation: lower latency wins, but Happy Eyeballs RFC usually favors v6
            # if it connects within a small delta of v4. Here we look at raw speed.
            if result.ipv6_rtt <= result.ipv4_rtt + 10: # +10ms bias buffer
                result.preference = "IPv6"
            else:
                result.preference = "IPv4"
        elif result.ipv6_rtt is not None:
            result.preference = "IPv6 Only"
        elif result.ipv4_rtt is not None:
            result.preference = "IPv4 Only"
        else:
            result.preference = "Failed"

    except Exception as e:
        result.error = str(e)

    return result

def main():
    print(f"--- Starting IPv6 Analysis for {INPUT_FILE} ---")
    
    domains_to_process = []
    
    # Read CSV
    try:
        with open(INPUT_FILE, mode='r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                domains_to_process.append(row)
    except FileNotFoundError:
        print(f"Error: File {INPUT_FILE} not found.")
        return

    results = []
    start_time = time.time()

    # Threaded Processing
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_domain = {executor.submit(analyze_domain, row): row['domain'] for row in domains_to_process}
        
        total = len(domains_to_process)
        completed = 0
        
        for future in as_completed(future_to_domain):
            data = future.result()
            results.append(data)
            completed += 1
            print(f"[{completed}/{total}] Analyzed: {data.domain}", end='\r')

    print(f"\nAnalysis complete in {time.time() - start_time:.2f} seconds.")

    # --- Statistics ---
    stats = {
        "total": len(results),
        "has_aaaa": 0,
        "ns_ipv6_ready": 0,
        "ipv6_reachable": 0,
        "prefers_ipv6": 0,
        "ipv6_unreachable_but_advertised": 0
    }

    for r in results:
        if r.has_aaaa: stats["has_aaaa"] += 1
        if r.ns_has_aaaa: stats["ns_ipv6_ready"] += 1
        if r.ipv6_reachable: stats["ipv6_reachable"] += 1
        if "IPv6" in r.preference: stats["prefers_ipv6"] += 1
        if r.has_aaaa and not r.ipv6_reachable: stats["ipv6_unreachable_but_advertised"] += 1

    # --- Write Report ---
    with open(OUTPUT_FILE, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Rank', 'Domain', 
            'Has_A_Record', 'Has_AAAA_Record', 'NS_Has_IPv6', 
            'IPv4_RTT_ms', 'IPv6_RTT_ms', 
            'IPv6_Reachable', 'Connection_Preference'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Sort results by rank for clean output
        results.sort(key=lambda x: int(x.rank))

        for r in results:
            writer.writerow({
                'Rank': r.rank,
                'Domain': r.domain,
                'Has_A_Record': r.has_a,
                'Has_AAAA_Record': r.has_aaaa,
                'NS_Has_IPv6': r.ns_has_aaaa,
                'IPv4_RTT_ms': r.ipv4_rtt if r.ipv4_rtt else '',
                'IPv6_RTT_ms': r.ipv6_rtt if r.ipv6_rtt else '',
                'IPv6_Reachable': r.ipv6_reachable,
                'Connection_Preference': r.preference
            })

    # --- Console Summary ---
    print("\n--- IPv6 Readiness Summary ---")
    print(f"Total Domains Analyzed: {stats['total']}")
    print(f"1. Domains with IPv6 (AAAA) Records:   {stats['has_aaaa']} ({stats['has_aaaa']/stats['total']*100:.1f}%)")
    print(f"2. Name Server Infrastructure IPv6:    {stats['ns_ipv6_ready']} ({stats['ns_ipv6_ready']/stats['total']*100:.1f}%)")
    print(f"3. Actual IPv6 Reachability (HTTPS):   {stats['ipv6_reachable']} ({stats['ipv6_reachable']/stats['total']*100:.1f}%)")
    print(f"4. Broken IPv6 (AAAA exists but fail): {stats['ipv6_unreachable_but_advertised']}")
    print(f"5. Connection Preference (IPv6):       {stats['prefers_ipv6']}")
    print(f"\nDetailed CSV report written to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()