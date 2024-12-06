import re
import csv
from collections import Counter, defaultdict
from datetime import datetime

# Importing Libraries for our code as - 
"""
    1. Re - For handling Regular Expressions inside our code 
    2. csv - to convert and set elements in rows and columns
    3. Collections Library  - In this we used Counter Fro counting hashable objects. For ip address and endpoints
"""

#  First Define threshold for suspicious activity as given in assignment to create a flag for sus activity

FAILED_USER_LOGIN_THRESHOLD = 10

# Regular expression to parse log lines
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>GET|POST|PUT|DELETE|HEAD) (?P<endpoint>/\S*).*?" (?P<status>\d{3}).*?(Invalid credentials)?'
)

"""
In this log pattern we can understand it in sections as -
1. To capture ip address we used : (?P<ip>\d+\.\d+\.\d+\.\d+)
2. to find method we used : (?P<method>GET|POST|PUT|DELETE|HEAD)
3. To find endpoints we used : (?P<endpoint>/\S*)
4. To find status code we used - (?P<status>\d{3})
5. To check Invalid Credentials we used - .*?(Invalid credentials)?
"""

# In this Function we initialize our data and then converted into CSV Format 


def generate_log_analysis_csv(file_path, output_file):
    # Data structures for analysis By giving Counter to it 
    request_counts = Counter()
    endpoint_counts = Counter()
    failed_logins = defaultdict(int)
    error_401_invalid_cred = 0  # Counter for 401 errors with "Invalid credentials"

    print("\n--- Starting log file analysis ---")

    # Step 1: Read and parse the log file
    print("Reading the log file...")
    with open(file_path, 'r') as file:
        total_lines = 0
        matched_lines = 0
        for line in file:
            total_lines += 1
            match = log_pattern.search(line)
            if match:
                matched_lines += 1
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
    print(f"Log file read successfully. Total lines: {total_lines}, Matched lines: {matched_lines}\n")

    # Step 2: Process parsed data
    print("Processing parsed data...")
    most_accessed_endpoints = endpoint_counts.most_common()
    highest_endpoint = most_accessed_endpoints[0] if most_accessed_endpoints else None
    #Here we are suing List comprehension to check , count failed logins  also highest no. of endpoint accessed
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_USER_LOGIN_THRESHOLD}
    print(f"Identified most accessed endpoint: {highest_endpoint}")
    print(f"Detected {len(suspicious_ips)} suspicious IPs exceeding login failure threshold.\n")

    # Step 3: Display and write results to CSV
    print(f"Writing results to '{output_file}'...")
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Report Header
        writer.writerow([f"Log Analysis Report"])
        writer.writerow([f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow([])  # Blank row for readability

        # Most Accessed Endpoint Section
        print("\nMOST ACCESSED ENDPOINT:")
        writer.writerow(["MOST ACCESSED ENDPOINT"])
        writer.writerow(["Endpoint", "Access Count"])
        if highest_endpoint:
            print(f"Endpoint: {highest_endpoint[0]}, Access Count: {highest_endpoint[1]}")
            writer.writerow([highest_endpoint[0], highest_endpoint[1]])
        else:
            print("No endpoints accessed.")
            writer.writerow(["No endpoints accessed", "N/A"])
        writer.writerow([])  # Blank row

        # All Endpoints Section
        print("\nALL ACCESSED ENDPOINTS:")
        writer.writerow(["ALL ACCESSED ENDPOINTS"])
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in most_accessed_endpoints:
            print(f"Endpoint: {endpoint}, Count: {count}")
            writer.writerow([endpoint, count])
        writer.writerow([])  # Blank row

        # Suspicious Activity Section
        print("\nSUSPICIOUS ACTIVITY:")
        writer.writerow(["SUSPICIOUS ACTIVITY"])
        writer.writerow(["IP Address", "Failed Login Count"])
        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                print(f"IP Address: {ip}, Failed Login Count: {count}")
                writer.writerow([ip, count])
        else:
            print("No suspicious activity detected.")
            writer.writerow(["No suspicious activity detected", "N/A"])
        writer.writerow([])  # Blank row

        # 401 Errors Section
        print("\n401 ERRORS WITH INVALID CREDENTIALS:")
        print(f"Total 401 Errors: {error_401_invalid_cred}")
        writer.writerow(["401 ERRORS WITH INVALID CREDENTIALS"])
        writer.writerow(["Total 401 Errors"])
        writer.writerow([error_401_invalid_cred])
        writer.writerow([])  # Blank row

        # Additional Insights
        print("\nADDITIONAL INSIGHTS:")
        print(f"Total Unique IPs: {len(request_counts)}")
        print(f"Total Unique Endpoints: {len(endpoint_counts)}")
        print(f"Total Requests: {sum(request_counts.values())}")
        writer.writerow(["ADDITIONAL INSIGHTS"])
        writer.writerow(["Total Unique IPs", len(request_counts)])
        writer.writerow(["Total Unique Endpoints", len(endpoint_counts)])
        writer.writerow(["Total Requests", sum(request_counts.values())])

    print(f"\nDetailed log analysis saved to '{output_file}'. Analysis complete.")

# Example usage
file_path = 'sample_test.log'  # Replace with the path to your log file
output_file = 'test_log_analysis_report.csv'

# Run the analysis
generate_log_analysis_csv(file_path, output_file)
