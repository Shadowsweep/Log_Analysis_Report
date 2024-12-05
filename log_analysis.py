import re
import csv
from collections import Counter, defaultdict
from datetime import datetime

# Define threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Regular expression to parse log lines
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>GET|POST|PUT|DELETE|HEAD) (?P<endpoint>/\S*).*?" (?P<status>\d{3}).*?(Invalid credentials)?'
)

# Data structures for analysis
request_counts = Counter()
endpoint_counts = Counter()
failed_logins = defaultdict(int)
error_401_invalid_cred = 0  # Counter for 401 errors with "Invalid credentials"

# Input file path
file_path = 'sample.log'
output_file = 'log_analysis_results.csv'

print("Starting log file analysis...")

# Parse the log file
print("Reading the log file...")
with open(file_path, 'r') as file:
    for line in file:
        match = log_pattern.search(line)
        if match:
            ip = match.group('ip')
            endpoint = match.group('endpoint')
            status = int(match.group('status'))
            invalid_creds = match.group(3)

            # Count requests per IP and endpoints
            request_counts[ip] += 1
            endpoint_counts[endpoint] += 1

            # Detect suspicious activity and count 401 errors with invalid credentials
            if status == 401:
                failed_logins[ip] += 1
                if invalid_creds:
                    error_401_invalid_cred += 1

print("Log file read and parsed successfully.")

# Identify the most frequently accessed endpoints in descending order
most_accessed_endpoints = endpoint_counts.most_common()
highest_endpoint = most_accessed_endpoints[0] if most_accessed_endpoints else None

# Filter suspicious IPs based on the threshold
suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

# Display the analysis results in the terminal
if highest_endpoint:
    endpoint, count = highest_endpoint
    print(f"\nMost Frequently Accessed Endpoint:\n{endpoint} (Accessed {count} times)")

print("\nEndpoints in Descending Order of Access Count:")
for endpoint, count in most_accessed_endpoints:
    print(f"{endpoint}: {count} times")

# Save results to a beautified CSV
print("\nSaving beautified results to CSV...")
with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)

    # Add a header for the CSV
    writer.writerow(["Log Analysis Report"])
    writer.writerow([f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
    writer.writerow([])  # Blank row

    # Most accessed endpoint
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    if highest_endpoint:
        writer.writerow([endpoint, count])
    writer.writerow([])  # Blank row

    # All accessed endpoints in descending order
    writer.writerow(["All Accessed Endpoints"])
    writer.writerow(["Endpoint", "Access Count"])
    for endpoint, count in most_accessed_endpoints:
        writer.writerow([endpoint, count])
    writer.writerow([])  # Blank row

    # Suspicious activity
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])
    else:
        writer.writerow(["No suspicious activity detected."])

    # 401 errors with invalid credentials
    writer.writerow([])  # Blank row
    writer.writerow(["401 Errors with Invalid Credentials"])
    writer.writerow(["Count"])
    writer.writerow([error_401_invalid_cred])

print(f" Results saved to '{output_file}'. Analysis complete.")
