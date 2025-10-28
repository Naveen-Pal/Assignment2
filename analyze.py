#!/usr/bin/env python3
"""
Analyze DNS Resolver Logs
-------------------------
Computes:
- Average lookup latency
- Average throughput
- Number of successful resolutions
- % of queries resolved from cache
- Number of failed resolutions
"""

import pandas as pd

# === CONFIG ===
FILE = "dns_logs.csv"   # replace with your actual filename

# === READ DATA ===
df = pd.read_csv(FILE)

# Convert time/latency fields
df['RTT(s)'] = pd.to_numeric(df['RTT(s)'], errors='coerce')
df['Cumulative Bytes'] = pd.to_numeric(df['Cumulative Bytes'], errors='coerce')

# === METRICS ===

# Total number of queries
total_queries = len(df)

# Successful resolutions (where Response type == "Response")
successful = df[df['Response type'].str.lower() == 'response'].shape[0]

# Failed resolutions
failed = df[df['Response type'].str.lower().isin(['failure', 'none'])].shape[0]

# Cache hits
cache_hits = df[df['Cache Status'].str.upper() == 'HIT'].shape[0]

# Average lookup latency (only valid ones)
avg_latency_ms = df['RTT(s)'].mean() * 1000

# Average throughput = total bytes / total time (in seconds)
total_bytes = df['Cumulative Bytes'].sum()
total_time_s = df['RTT(s)'].sum()
avg_throughput = total_bytes / total_time_s if total_time_s > 0 else 0

# Cache %
cache_percent = (cache_hits / total_queries) * 100 if total_queries > 0 else 0

# === PRINT RESULTS ===
print("📊 DNS Resolver Analysis Report")
print("---------------------------------")
print(f"Total Queries: {total_queries}")
print(f"Successful Resolutions: {successful}")
print(f"Failed Resolutions: {failed}")
print(f"Cache Hits: {cache_hits} ({cache_percent:.2f}%)")
print(f"Average Lookup Latency: {avg_latency_ms:.2f} ms")
print(f"Average Throughput: {avg_throughput:.2f} bytes/sec")

# Optional: save summary to file
summary = {
    "Total Queries": total_queries,
    "Successful Resolutions": successful,
    "Failed Resolutions": failed,
    "Cache Hits": cache_hits,
    "Cache %": round(cache_percent, 2),
    "Average Latency (ms)": round(avg_latency_ms, 2),
    "Average Throughput (bytes/sec)": round(avg_throughput, 2),
}
pd.DataFrame([summary]).to_csv("dns_analysis_summary.csv", index=False)
print("\n✅ Saved summary to dns_analysis_summary.csv")
