import pandas as pd
from collections import Counter

# Load the CSV from analysis folder
data = pd.read_csv("../analysis/packets.csv")

# Threshold: if a source IP sends more than X SYN packets, flag it
scan_threshold = 30
alerts = []

# Count SYN packets per source IP
for ip, count in Counter(data["ip.src"]).items():
    if count > scan_threshold:
        alerts.append({"attacker_ip": ip, "syn_count": count})

# Save alerts to analysis folder
if alerts:
    pd.DataFrame(alerts).to_csv("../analysis/scan_alerts.csv", index=False)
    print("⚠️ Port scan detected! Alerts saved to scan_alerts.csv")
else:
    print("✅ No port scans detected.")
