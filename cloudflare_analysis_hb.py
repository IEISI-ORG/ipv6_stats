import asyncio
import csv
import time
import sys
import socket

# dependency check
try:
    import dns.asyncresolver
    import dns.resolver
    from dns.exception import DNSException
except ImportError:
    print("Error: 'dnspython' is not installed. Please run: pip install dnspython")
    sys.exit(1)

# --- Configuration ---
INPUT_FILE = 'cloudflare-radar_top-100-domains_au_20251116-20251123.csv'
OUTPUT_FILE = 'ipv6_happy_eyeballs_report.csv'
CONCURRENCY = 30       # Reduced slightly to prevent OS socket exhaustion
TIMEOUT = 5.0          # Increased timeout for reliability
HE_DELAY = 0.25        # 250ms delay for IPv4 (RFC 8305)

class DomainResult:
    def __init__(self, domain, rank):
        self.domain = domain
        self.rank = rank
        self.has_a = False
        self.has_aaaa = False
        self.ns_has_aaaa = False
        self.ipv4_rtt = None
        self.ipv6_rtt = None
        self.race_winner = "N/A"
        self.race_margin_ms = 0
        self.ipv6_reachable = False
        self.error = None

async def safe_resolve(domain, record_type):
    """Resolves DNS without crashing."""
    try:
        # Use default resolver
        answer = await dns.asyncresolver.resolve(domain, record_type)
        return [r.to_text() for r in answer]
    except Exception:
        return []

async def check_ns_ipv6(domain):
    """Checks authoritative NS for AAAA records."""
    try:
        ns_records = await safe_resolve(domain, 'NS')
        for ns in ns_records:
            # Resolve the NS target (e.g., ns1.google.com -> AAAA?)
            # Note: ns_records returns text like 'ns1.google.com.', strip trailing dot
            target = ns.rstrip('.')
            aaaa = await safe_resolve(target, 'AAAA')
            if aaaa:
                return True
        return False
    except Exception:
        return False

async def tcp_connect(ip, port=443, delay=0):
    """Tries to connect to IP. Returns (Success_Bool, RTT_ms, IP_Used)."""
    if delay > 0:
        await asyncio.sleep(delay)
    
    start = time.time()
    try:
        # Open connection directly to IP
        conn = asyncio.open_connection(ip, port)
        _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
        
        # Measure time
        rtt = (time.time() - start) * 1000
        
        # Close immediately
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass # Ignore errors during close
            
        return True, rtt, ip
    except Exception:
        return False, None, ip

async def simulate_race(ipv4, ipv6):
    """
    Simulates RFC 8305:
    1. Fire IPv6
    2. Wait 250ms
    3. Fire IPv4
    4. Return winner.
    """
    # Create tasks
    task_v6 = asyncio.create_task(tcp_connect(ipv6, 443, delay=0))
    task_v4 = asyncio.create_task(tcp_connect(ipv4, 443, delay=HE_DELAY))

    pending = {task_v6, task_v4}
    winner_name = "Failed"
    margin = 0

    while pending:
        # Wait for the next task to finish
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        
        for task in done:
            success, rtt, ip = task.result()
            if success:
                # We have a winner!
                # Cancel the other task immediately
                for p in pending: p.cancel()
                
                if ip == ipv6:
                    return "IPv6", rtt # Return raw time as margin base
                else:
                    return "IPv4", rtt
                
    return "Failed", 0

async def analyze_wrapper(row, semaphore, progress_counter):
    """
    Wrapper to handle semaphore and progress counting.
    """
    async with semaphore:
        try:
            res = await analyze_domain(row)
        except Exception as e:
            # Fallback if analysis crashes
            try:
                d_name = row.get('domain', 'unknown')
                r_rank = row.get('rank', '0')
            except:
                d_name = "parse_error"
                r_rank = 0
            res = DomainResult(d_name, r_rank)
            res.error = f"CRASH: {str(e)}"
        
        progress_counter[0] += 1
        print(f"Progress: {progress_counter[0]}/{progress_counter[1]}", end='\r')
        return res

async def analyze_domain(row):
    # Parse Row
    try:
        rank = row.get('rank', list(row.values())[0])
        domain = row.get('domain', list(row.values())[1])
    except:
        return DomainResult("ParseError", 0)

    res = DomainResult(domain, rank)

    # 1. DNS Resolution (Parallel)
    # We fetch A, AAAA, and check NS infrastructure simultaneously
    rec_a, rec_aaaa, ns_v6_bool = await asyncio.gather(
        safe_resolve(domain, 'A'),
        safe_resolve(domain, 'AAAA'),
        check_ns_ipv6(domain)
    )

    res.has_a = bool(rec_a)
    res.has_aaaa = bool(rec_aaaa)
    res.ns_has_aaaa = ns_v6_bool

    target_v4 = rec_a[0] if rec_a else None
    target_v6 = rec_aaaa[0] if rec_aaaa else None

    # 2. Basic RTT Measurement (Sequential-ish for accuracy, or parallel)
    # We just need to know if they are reachable individually
    if target_v4:
        s, t, _ = await tcp_connect(target_v4)
        if s: res.ipv4_rtt = t
        
    if target_v6:
        s, t, _ = await tcp_connect(target_v6)
        if s: 
            res.ipv6_rtt = t
            res.ipv6_reachable = True

    # 3. Happy Eyeballs Race
    # Only race if we have both candidates
    if target_v4 and target_v6:
        winner, finish_time = await simulate_race(target_v4, target_v6)
        res.race_winner = winner
    elif target_v6 and res.ipv6_reachable:
        res.race_winner = "IPv6 Only"
    elif target_v4 and res.ipv4_rtt:
        res.race_winner = "IPv4 Only"
    else:
        res.race_winner = "Both Failed"

    return res

async def main():
    print(f"--- Starting Analysis on {INPUT_FILE} ---")
    
    # 1. Load Data
    rows = []
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    total_domains = len(rows)
    if total_domains == 0:
        print("CSV is empty.")
        return

    print(f"Loaded {total_domains} domains. Starting {CONCURRENCY} workers...")

    # 2. Setup Progress Tracker
    # [current, total] - mutable list to pass by reference
    progress = [0, total_domains]
    semaphore = asyncio.Semaphore(CONCURRENCY)

    # 3. Create Tasks
    tasks = [analyze_wrapper(row, semaphore, progress) for row in rows]

    # 4. EXECUTE - This will wait for ALL tasks
    # return_exceptions=True ensures one crash doesn't stop the whole list
    results = await asyncio.gather(*tasks, return_exceptions=True)

    print(f"\nProcessing Complete. Writing results...")

    # 5. Filter out Exceptions from results list (if any slipped through wrapper)
    clean_results = []
    for r in results:
        if isinstance(r, DomainResult):
            clean_results.append(r)
        else:
            print(f"Warning: A task returned an unexpected error: {r}")

    # 6. Sort and Save
    try:
        clean_results.sort(key=lambda x: int(x.rank) if str(x.rank).isdigit() else 9999)
    except:
        pass # Sort fail is fine

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        headers = [
            'Rank', 'Domain', 
            'Has_A', 'Has_AAAA', 'NS_Infrastructure_IPv6',
            'IPv6_Reachable',
            'IPv4_RTT', 'IPv6_RTT',
            'Happy_Eyeballs_Winner'
        ]
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        
        for r in clean_results:
            writer.writerow({
                'Rank': r.rank,
                'Domain': r.domain,
                'Has_A': r.has_a,
                'Has_AAAA': r.has_aaaa,
                'NS_Infrastructure_IPv6': r.ns_has_aaaa,
                'IPv6_Reachable': r.ipv6_reachable,
                'IPv4_RTT': f"{r.ipv4_rtt:.1f}" if r.ipv4_rtt else '',
                'IPv6_RTT': f"{r.ipv6_rtt:.1f}" if r.ipv6_rtt else '',
                'Happy_Eyeballs_Winner': r.race_winner
            })

    print(f"Results saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    # Windows Loop Fix
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted by user.")