# Python-Inter-Assessment-VRV
This script analyzes a log file to find how often each IP address makes requests, which endpoints are accessed the most, and whether any IPs have suspicious activity like repeated failed logins. It uses regular expressions to extract IP addresses, endpoints, and status codes from each log entry. It counts the total requests for each IP, the number of times each endpoint is accessed, and tracks failed logins (e.g., error 401 or "Invalid credentials"). It identifies the most accessed endpoint and highlights IPs with too many failed login attempts. The results are shown in the console and saved to a CSV file, making it easy to review the activity and detect possible issues.

# Requests per IP
This section displays the number of requests made by each IP address.

IP Address: The origin of the requests.
Request Count: The total number of requests from the IP address.

# Most Accessed Endpoint
This section highlights the endpoint (URL or resource path) accessed the most.

Endpoint: The resource accessed most frequently.
Access Count: The number of times this endpoint was accessed.

# Suspicious Activity
This section identifies IP addresses showing unusual behavior, such as a high number of failed login attempts.

IP Address: The IP address with suspicious activity.
Failed Login Count: The total failed login attempts from this IP address.


# log analysis results
IP Requests
IP Address,Request Count
203.0.113.5,8
198.51.100.23,8
192.168.1.1,7
10.0.0.2,6
192.168.1.100,5

Most Accessed Endpoint
Endpoint,Access Count
/login,13

Suspicious Activity
IP Address,Failed Login Count
