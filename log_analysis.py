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

def generate_log_analysis_csv(file_path, output_file):
    # Data structures for analysis
    request_counts = Counter()
    endpoint_counts = Counter()
    failed_logins = defaultdict(int)
    error_401_invalid_cred = 0  # Counter for 401 errors with "Invalid credentials"

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
                invalid_creds = match.group(4)

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

    # Write results to CSV
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Report Header
        writer.writerow([f"Log Analysis Report"])
        writer.writerow([f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow([])  # Blank row for readability

        # Most Accessed Endpoint Section
        writer.writerow(["MOST ACCESSED ENDPOINT"])
        writer.writerow(["Endpoint", "Access Count"])
        if highest_endpoint:
            writer.writerow([highest_endpoint[0], highest_endpoint[1]])
        else:
            writer.writerow(["No endpoints accessed", "N/A"])
        writer.writerow([])  # Blank row

        # All Endpoints Section
        writer.writerow(["ALL ACCESSED ENDPOINTS"])
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in most_accessed_endpoints:
            writer.writerow([endpoint, count])
        writer.writerow([])  # Blank row

        # Suspicious Activity Section
        writer.writerow(["SUSPICIOUS ACTIVITY"])
        writer.writerow(["IP Address", "Failed Login Count"])
        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["No suspicious activity detected", "N/A"])
        writer.writerow([])  # Blank row

        # 401 Errors Section
        writer.writerow(["401 ERRORS WITH INVALID CREDENTIALS"])
        writer.writerow(["Total 401 Errors"])
        writer.writerow([error_401_invalid_cred])
        writer.writerow([])  # Blank row

        # Additional Insights
        writer.writerow(["ADDITIONAL INSIGHTS"])
        writer.writerow(["Total Unique IPs", len(request_counts)])
        writer.writerow(["Total Unique Endpoints", len(endpoint_counts)])
        writer.writerow(["Total Requests", sum(request_counts.values())])

    print(f"Detailed log analysis saved to '{output_file}'. Analysis complete.")

# Example usage
file_path = 'sample_test.log'
output_file = 'test_log_analysis_report.csv'

# Run the analysis
generate_log_analysis_csv(file_path, output_file)