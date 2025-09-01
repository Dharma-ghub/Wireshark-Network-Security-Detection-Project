import subprocess
import pandas as pd
import glob
import matplotlib.pyplot as plt

# --------------------------
# 1️⃣ Run detection scripts
# --------------------------
print("Running detection scripts...")

scripts = ["detect_scans.py", "detect_dns.py"]

for script in scripts:
    print(f"Running {script}...")
    subprocess.run(["python3", f"scripts/{script}"])

# --------------------------
# 2️⃣ Consolidate alerts
# --------------------------
alert_files = glob.glob("analysis/*alerts.csv")
all_alerts = pd.DataFrame()

for file in alert_files:
    try:
        df = pd.read_csv(file)
        all_alerts = pd.concat([all_alerts, df], ignore_index=True)
    except pd.errors.EmptyDataError:
        print(f"{file} is empty, skipping.")

all_alerts.to_csv("analysis/all_alerts.csv", index=False)
print("✅ All alerts consolidated into all_alerts.csv")

# --------------------------
# 3️⃣ Summary Report
# --------------------------
if not all_alerts.empty:
    print("\nSummary by attacker IP:")
    print(all_alerts['attacker_ip'].value_counts())

    if 'suspicious_domain' in all_alerts.columns:
        print("\nSuspicious domain counts:")
        print(all_alerts['suspicious_domain'].value_counts())

    # --------------------------
    # 4️⃣ Generate Graphs
    # --------------------------
    print("\nGenerating graphs...")

    # Top 10 attacker IPs
    top_ips = all_alerts['attacker_ip'].value_counts().head(10)
    plt.figure(figsize=(10,5))
    top_ips.plot(kind='bar', title="Top Attacker IPs")
    plt.xlabel("IP Address")
    plt.ylabel("Number of Alerts")
    plt.tight_layout()
    plt.savefig("analysis/top_attacker_ips.png")
    plt.show()
else:
    print("✅ No alerts detected. Nothing to display.")
