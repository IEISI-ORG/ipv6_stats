import asyncio
import csv
import time
import sys
import socket
import ssl

# Dependency check
try:
    import dns.asyncresolver
    import dns.resolver
except ImportError:
    print("Error: 'dnspython' is not installed. Please run: pip install dnspython")
    sys.exit(1)

# --- Configuration ---
INPUT_FILE = 'cloudflare-radar_top-100-domains_au_20251116-20251123.csv'
OUTPUT_FILE = 'ipv6_happy_eyeballs_tls_report.csv'
CONCURRENCY = 20       # Lower concurrency slightly as SSL handshakes are more CPU intensive
TIMEOUT = 6.0          # TLS takes longer than raw TCP
HE_DELAY = 0.25        # 250ms RFC 8305 delay

# --- SSL Context Setup ---
# We create a context that performs the handshake but ignores certificate validity errors
# (Host matching often fails when we manually route IPs, but the RTT measurement remains valid)
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

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
        answer = await dns.asyncresolver.resolve(domain, record_type)
        return [r.to_text() for r in answer]
    except Exception:
        return []

async def check_ns_ipv6(domain):
    try:
        ns_records = await safe_resolve(domain, 'NS')
        for ns in ns_records:
            target = ns.rstrip('.')
            aaaa = await safe_resolve(target, 'AAAA')
            if aaaa: return True
        return False
    except Exception:
        return False

async def tls_connect(ip, domain, port=443, delay=0):
    """
    Attempts a full TLS Handshake to the specific IP, using SNI for the domain.
    Returns (Success_Bool, RTT_ms, IP_Used).
    """
    if delay > 0:
        await asyncio.sleep(delay)
    
    start = time.time()
    writer = None
    try:
        # This performs TCP Connect + TLS Handshake
        # server_hostname ensures SNI is sent (Crucial for Cloudflare/Google/AWS)
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=ip, 
                port=port, 
                ssl=SSL_CONTEXT, 
                server_hostname=domain 
            ),
            timeout=TIMEOUT
        )
        
        # If we reach here, SSL Handshake is complete.
        rtt = (time.time() - start) * 1000
        
        # Cleanup
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
            
        return True, rtt, ip
    except Exception:
        # Common errors: SSL handshake timeout, Connection Reset by Peer
        if writer:
            try:
                writer.close()
            except:
                pass
        return False, None, ip

async def simulate_race(ipv4, ipv6, domain):
    """
    Simulates RFC 8305 Happy Eyeballs using TLS Handshakes.
    """
    # 1. Start IPv6
    task_v6 = asyncio.create_task(tls_connect(ipv6, domain, 443, delay=0))
    # 2. Start IPv4 after delay
    task_v4 = asyncio.create_task(tls_connect(ipv4, domain, 443, delay=HE_DELAY))

    pending = {task_v6, task_v4}
    
    # Wait for FIRST success
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        
        for task in done:
            success, rtt, ip = task.result()
            if success:
                # Cancel loser
                for p in pending: p.cancel()
                
                if ip == ipv6:
                    return "IPv6", rtt
                else:
                    return "IPv4", rtt
                
    return "Failed", 0

async def analyze_wrapper(row, semaphore, progress_counter):
    async with semaphore:
        try:
            res = await analyze_domain(row)
        except Exception as e:
            res = DomainResult(row.get('domain', 'Err'), row.get('rank', 0))
            res.error = str(e)
        
        progress_counter[0] += 1
        print(f"Progress: {progress_counter[0]}/{progress_counter[1]}", end='\r')
        return res

async def analyze_domain(row):
    try:
        rank = row.get('rank', list(row.values())[0])
        domain = row.get('domain', list(row.values())[1])
    except:
        return DomainResult("ParseError", 0)

    res = DomainResult(domain, rank)

    # 1. DNS Resolution
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

    # 2. Individual RTT (Using TLS now)
    # We test them individually to get raw stats
    if target_v4:
        s, t, _ = await tls_connect(target_v4, domain)
        if s: res.ipv4_rtt = t
        
    if target_v6:
        s, t, _ = await tls_connect(target_v6, domain)
        if s: 
            res.ipv6_rtt = t
            res.ipv6_reachable = True

    # 3. Happy Eyeballs Race
    if target_v4 and target_v6:
        winner, _ = await simulate_race(target_v4, target_v6, domain)
        res.race_winner = winner
    elif target_v6 and res.ipv6_reachable:
        res.race_winner = "IPv6 Only"
    elif target_v4 and res.ipv4_rtt:
        res.race_winner = "IPv4 Only"
    else:
        res.race_winner = "Both Failed"

    return res

async def main():
    print(f"--- Async IPv6 Analysis (TLS/SNI Enabled) ---")
    
    rows = []
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except Exception as e:
        print(f"Error: {e}")
        return

    progress = [0, len(rows)]
    semaphore = asyncio.Semaphore(CONCURRENCY)

    tasks = [analyze_wrapper(row, semaphore, progress) for row in rows]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    print(f"\nAnalysis Complete. Saving...")
    
    # Filter and Sort
    clean_results = [r for r in results if isinstance(r, DomainResult)]
    clean_results.sort(key=lambda x: int(x.rank) if str(x.rank).isdigit() else 9999)

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        headers = [
            'Rank', 'Domain', 
            'Has_A', 'Has_AAAA', 'NS_Infrastructure_IPv6',
            'IPv6_Reachable',
            'IPv4_RTT_TLS', 'IPv6_RTT_TLS',
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
                'IPv4_RTT_TLS': f"{r.ipv4_rtt:.1f}" if r.ipv4_rtt else '',
                'IPv6_RTT_TLS': f"{r.ipv6_rtt:.1f}" if r.ipv6_rtt else '',
                'Happy_Eyeballs_Winner': r.race_winner
            })

    print(f"Report saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())