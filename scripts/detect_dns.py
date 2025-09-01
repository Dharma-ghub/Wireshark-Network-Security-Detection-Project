import pandas as pd
from collections import Counter
import os

file_path = "../analysis/dns_queries_with_header.csv"

if os.stat(file_path).st_size == 0:
    print("⚠️ CSV is empty")
    exit()

# Define columns
columns = ["time", "ip_src", "ip_dst", "dns_query"]

# Read CSV with tab separator
data = pd.read_csv(file_path, sep="\t", names=columns, header=None)

# Strip whitespace and ensure strings
data["ip_src"] = data["ip_src"].astype(str).str.strip()
data["dns_query"] = data["dns_query"].astype(str).str.strip()

# Threshold for query counts
threshold = 5
alerts = []

# Count queries per IP
counts = Counter(data["ip_src"])
print("Counts per IP:", counts)

for ip, count in counts.items():
    if count >= threshold:
        alerts.append({"attacker_ip": ip, "query_count": count})

# Detect suspicious domains
suspicious_domains = data[data["dns_query"].str.contains(r'\.xyz|\.top|\.club', na=False)]
for index, row in suspicious_domains.iterrows():
    alerts.append({"attacker_ip": row["ip_src"], "suspicious_domain": row["dns_query"]})

# Save alerts
if alerts:
    pd.DataFrame(alerts).to_csv("../analysis/dns_alerts.csv", index=False)
    print("⚠️ DNS anomalies detected! Alerts saved.")
else:
    print("✅ No DNS anomalies detected.")
