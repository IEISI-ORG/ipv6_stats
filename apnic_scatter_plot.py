import argparse
import requests
import pandas as pd
import matplotlib.pyplot as plt
import re
import numpy as np

# URLs for the live data
URL_CAPABILITY = "https://stats.labs.apnic.net/ipv6"
URL_PERFORMANCE = "https://stats.labs.apnic.net/v6perf"
CSV_FILENAME = "apnic_ipv6_data.csv"
PNG_FILENAME = "apnic_scatter.png"
MIN_SAMPLES = 1000

def fetch_data(url):
    print(f"Fetching raw source from {url}...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.text

def extract_ipv6_capability(html_text):
    data = []
    # Pattern: ["<a href=\"/ipv6/CODE\">...{v: 80.14,
    pattern = re.compile(r'\["<a href=\\"/ipv6/([A-Z0-9]{2})\\">.*?\{v:\s*([\d\.]+),')
    matches = pattern.findall(html_text)
    for cc, cap_pct in matches:
        data.append({'Code': cc, 'IPv6_Capable_Pct': float(cap_pct)})
    return pd.DataFrame(data)

def extract_ipv6_performance(html_text):
    data = []
    # Extract CC, RTT Diff, AND Sample Count
    # Pattern looks for: ["<a href...Code...HTML...", RTT, Samples,
    pattern = re.compile(r'\["<a href=\\"/v6perf/([A-Z0-9]{2})\\">.*?",\s*(-?[\d\.]+),\s*(\d+)')
    matches = pattern.findall(html_text)
    for cc, rtt, samples in matches:
        data.append({
            'Code': cc, 
            'Mean_RTT_Diff': float(rtt),
            'Samples': int(samples)
        })
    return pd.DataFrame(data)

def save_csv(df):
    """Saves the merged data to CSV, sorted by adoption."""
    df_sorted = df.sort_values(by='IPv6_Capable_Pct', ascending=False)
    df_sorted.to_csv(CSV_FILENAME, index=False)
    print(f"\n[+] Raw data saved to: {CSV_FILENAME}")

def summarize(df):
    """Prints a statistical summary."""

    # 1. Calculate Weighted Averages (Global experience)
    total_samples = df['Samples'].sum()
    weighted_cap = (df['IPv6_Capable_Pct'] * df['Samples']).sum() / total_samples
    weighted_rtt = (df['Mean_RTT_Diff'] * df['Samples']).sum() / total_samples

    # 2. Print Summary
    print("-" * 60)
    print(f"       APNIC IPV6 DATA SUMMARY ({len(df)} Economies)")
    print("-" * 60)
    print(f"Global Weighted Avg Adoption:   {weighted_cap:.2f}%")
    print(f"Global Weighted Avg RTT Diff:   {weighted_rtt:.2f} ms")
    if weighted_rtt < 0:
        print("(On average, IPv6 is faster than IPv4 globally)")
    else:
        print("(On average, IPv4 is faster than IPv6 globally)")
    
    # Filter for reasonable samples to avoid tiny island noise in the rankings
    df_significant = df[df['Samples'] > MIN_SAMPLES]

    print("-" * 60)
    print(f"TOP 5 ADOPTERS (Highest % Capable, >{MIN_SAMPLES} samples):")
    print(df_significant.nlargest(5, 'IPv6_Capable_Pct')[['Code', 'IPv6_Capable_Pct', 'Mean_RTT_Diff']].to_string(index=False))

    print("-" * 60)
    print("FASTEST IPV6 RELATIVE TO IPV4 (Lowest/Negative RTT):")
    print(df_significant.nsmallest(5, 'Mean_RTT_Diff')[['Code', 'IPv6_Capable_Pct', 'Mean_RTT_Diff']].to_string(index=False))

    print("-" * 60)
    print("SLOWEST IPV6 RELATIVE TO IPV4 (Highest Positive RTT):")
    print(df_significant.nlargest(5, 'Mean_RTT_Diff')[['Code', 'IPv6_Capable_Pct', 'Mean_RTT_Diff']].to_string(index=False))
    print("-" * 60)

# Candidate label offsets in points, tried in order until one doesn't collide
LABEL_OFFSETS = [(0, 14), (0, -14), (18, 0), (-18, 0),
                 (14, 14), (-14, 14), (14, -14), (-14, -14),
                 (0, 28), (0, -28), (28, 0), (-28, 0)]

def annotate_without_overlap(ax, rows):
    """Labels points by Code, nudging each label until it clears earlier ones."""
    renderer = ax.figure.canvas.get_renderer()
    placed = []
    for _, row in rows.iterrows():
        for dx, dy in LABEL_OFFSETS:
            label = ax.annotate(
                row['Code'], (row['IPv6_Capable_Pct'], row['Mean_RTT_Diff']),
                xytext=(dx, dy), textcoords='offset points',
                fontsize=10, fontweight='bold', color='black', ha='center', va='center',
                arrowprops=dict(arrowstyle='-', color='black', lw=0.6, shrinkA=0, shrinkB=2))
            bbox = label.get_window_extent(renderer).expanded(1.1, 1.2)
            if not any(bbox.overlaps(other) for other in placed):
                placed.append(bbox)
                break
            label.remove()
        else:
            # Every candidate collided: keep the last one rather than drop the label
            placed.append(bbox)
            ax.add_artist(label)

def fetch_merged():
    """Fetches live APNIC data and merges capability with performance."""
    html_cap = fetch_data(URL_CAPABILITY)
    df_cap = extract_ipv6_capability(html_cap)

    html_perf = fetch_data(URL_PERFORMANCE)
    df_perf = extract_ipv6_performance(html_perf)

    if df_cap.empty or df_perf.empty:
        return None

    df_merged = pd.merge(df_cap, df_perf, on='Code', how='inner')

    # Filter out Regions (codes starting with X or Q)
    df_merged = df_merged[~df_merged['Code'].str.startswith('X')]
    df_merged = df_merged[~df_merged['Code'].str.startswith('Q')]
    return df_merged

def main():
    parser = argparse.ArgumentParser(description="APNIC IPv6 adoption vs performance scatter plot")
    parser.add_argument("--csv", help="Plot an existing CSV (e.g. a snapshot) instead of fetching live data")
    parser.add_argument("--out", default=PNG_FILENAME, help=f"Output PNG path (default: {PNG_FILENAME})")
    parser.add_argument("--title-suffix", default="", help="Appended to the chart title, e.g. a date")
    args = parser.parse_args()

    # 1. Load: from a saved CSV, or fetch live and save
    if args.csv:
        df_merged = pd.read_csv(args.csv)
        print(f"[+] Loaded {len(df_merged)} economies from: {args.csv}")
    else:
        df_merged = fetch_merged()
        if df_merged is None:
            print("Error: No data extracted.")
            return
        save_csv(df_merged)

    # 2. Print Text Summary
    summarize(df_merged)

    # 4. Prepare for Plotting (Clean extreme outliers for chart readability)
    df_clean = df_merged[abs(df_merged['Mean_RTT_Diff']) < 300].copy()
    
    # Calculate Bubble Size (Logarithmic)
    df_clean['Bubble_Size'] = np.log10(df_clean['Samples'] + 1) * 30

    # 5. Plotting
    plt.figure(figsize=(14, 10))
    
    x = df_clean['IPv6_Capable_Pct']
    y = df_clean['Mean_RTT_Diff']
    w = df_clean['Samples']

    # Unweighted Trend (Black Dashed)
    z = np.polyfit(x, y, 1)
    p = np.poly1d(z)
    plt.plot(x, p(x), "k--", linewidth=1, alpha=0.5, label="Trend (By Country)")

    # Weighted Trend (Blue Solid)
    z_weighted = np.polyfit(x, y, 1, w=np.sqrt(w)) 
    p_weighted = np.poly1d(z_weighted)
    
    # Calculate correlation for label
    correlation_matrix = np.corrcoef(x, y)
    r_squared = correlation_matrix[0,1]**2
    
    plt.plot(x, p_weighted(x), "b-", linewidth=2, alpha=0.8, label=f"Trend (Weighted by Vol)")

    # Scatter
    plt.scatter(
        x, y, 
        s=df_clean['Bubble_Size'], 
        alpha=0.5, 
        edgecolors='black', 
        linewidth=0.5,
        c='#1f77b4', 
        label='Economies'
    )

    # Reference Lines
    plt.axhline(0, color='red', linestyle='-', linewidth=1, label='Parity (IPv6 = IPv4)')
    plt.axvline(50, color='gray', linestyle=':', alpha=0.3)

    # Invert Y (Negative is UP/Better)
    plt.gca().invert_yaxis()


    plt.title(f'IPv6 Adoption vs Performance (Source: APNIC Labs){args.title_suffix}', fontsize=16)
    plt.xlabel('IPv6 Capable (%)', fontsize=12)
    plt.ylabel('Mean RTT Difference (ms)\n(UP = IPv6 Faster | DOWN = IPv4 Faster)', fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend(loc='lower right')
    
    plt.tight_layout()

    # Annotate Top 5 by Volume (after layout, so label extents are final)
    top_vol = df_clean.nlargest(5, 'Samples')
    annotate_without_overlap(plt.gca(), top_vol)

    plt.savefig(args.out, dpi=120)
    print(f"[+] Chart saved to: {args.out}")
    plt.show()

if __name__ == "__main__":
    main()
