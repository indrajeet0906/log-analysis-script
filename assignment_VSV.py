import re
import csv
from collections import Counter, defaultdict

log_data = """
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312
198.51.100.23 - - [03/Dec/2024:10:12:38 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:39 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:40 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:41 +0000] "GET /dashboard HTTP/1.1" 200 1024
198.51.100.23 - - [03/Dec/2024:10:12:42 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:43 +0000] "GET /dashboard HTTP/1.1" 200 1024
203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:45 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:46 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:47 +0000] "GET /profile HTTP/1.1" 200 768
192.168.1.1 - - [03/Dec/2024:10:12:48 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:49 +0000] "POST /feedback HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:50 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.1 - - [03/Dec/2024:10:12:51 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:52 +0000] "GET /about HTTP/1.1" 200 256
203.0.113.5 - - [03/Dec/2024:10:12:53 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:54 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:55 +0000] "GET /contact HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:56 +0000] "GET /home HTTP/1.1" 200 512
192.168.1.100 - - [03/Dec/2024:10:12:57 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:58 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:59 +0000] "GET /dashboard HTTP/1.1" 200 1024
192.168.1.1 - - [03/Dec/2024:10:13:00 +0000] "GET /about HTTP/1.1" 200 256
198.51.100.23 - - [03/Dec/2024:10:13:01 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:13:02 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:13:03 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:13:04 +0000] "GET /profile HTTP/1.1" 200 768
198.51.100.23 - - [03/Dec/2024:10:13:05 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:13:06 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:13:07 +0000] "POST /feedback HTTP/1.1" 200 128
"""

log_file = "log_data.csv"
with open(log_file, "w", newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Log Entry"]) 
    for line in log_data.strip().split("\n"):
        writer.writerow([line])

print(f"Log data saved to {log_file}.")

def parse_log_line(line):
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d.\d" (?P<status>\d+) (?P<size>\d+).*'
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

log_entries = []
with open(log_file, "r") as file:
    reader = csv.reader(file)
    next(reader)  
    for row in reader:
        parsed_entry = parse_log_line(row[0])
        if parsed_entry:
            log_entries.append(parsed_entry)

ip_counter = Counter(entry['ip'] for entry in log_entries)
endpoint_counter = Counter(entry['endpoint'] for entry in log_entries)
most_accessed_endpoint = endpoint_counter.most_common(1)[0]

failed_logins = defaultdict(int)
threshold = 10  
for entry in log_entries:
    if entry['status'] == '401':
        failed_logins[entry['ip']] += 1

print("Requests per IP:")
print("IP Address           Request Count")
for ip, count in ip_counter.most_common():
    print(f"{ip:<20}{count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

threshold = 1  
failed_logins = defaultdict(int)

for entry in log_entries:
    if entry['status'] == '401':  
        failed_logins[entry['ip']] += 1


suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}


print("\nSuspicious Activity Detected:")
if suspicious_ips:
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20}{count}")
else:
    print("No suspicious activity detected.")

output_file = 'log_analysis_result.csv'


with open(output_file, 'w', newline='') as file:
    writer = csv.writer(file)

    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(ip_counter.items())

    
    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

    
    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    if suspicious_ips:
        writer.writerows(suspicious_ips.items())
    else:
        writer.writerow(["No suspicious activity detected."])

print(f"\nAnalysis complete. Results saved to {output_file}.")
