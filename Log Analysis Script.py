import re
import csv
from collections import Counter

def parse_log_file(log_path, failure_threshold=10):
   
    ip_requests = Counter()
    endpoint_counts = Counter()
    failed_logins = Counter()
    
    ip_pattern = r'^(\d+\.\d+\.\d+\.\d+)'
    endpoint_pattern = r'"(?:GET|POST) (/\w+)'
    status_pattern = r' (\d{3}) '
    
    with open(log_path, 'r') as log_file:
        for line in log_file:
            
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1
            
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1
            
            if '401' in line or 'Invalid credentials' in line:
                failed_logins[ip] += 1
    
    
    most_accessed_endpoint = endpoint_counts.most_common(1)[0]
    
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > failure_threshold}
    
    return {
        'ip_requests': dict(ip_requests.most_common()),
        'most_accessed_endpoint': most_accessed_endpoint,
        'suspicious_ips': suspicious_ips
    }

def save_results_to_csv(analysis_results, output_path='log_analysis_results.csv'):
    
    with open(output_path, 'w', newline='') as csvfile:
        
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['IP Requests'])
        csvwriter.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(analysis_results['ip_requests'].items(), key=lambda x: x[1], reverse=True):
            csvwriter.writerow([ip, count])
        
        csvwriter.writerow([])
        csvwriter.writerow(['Most Accessed Endpoint'])
        csvwriter.writerow(['Endpoint', 'Access Count'])
        csvwriter.writerow([analysis_results['most_accessed_endpoint'][0], analysis_results['most_accessed_endpoint'][1]])

        csvwriter.writerow([])
        csvwriter.writerow(['Suspicious Activity'])
        csvwriter.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in sorted(analysis_results['suspicious_ips'].items(), key=lambda x: x[1], reverse=True):
            csvwriter.writerow([ip, count])

def display_results(analysis_results):
    print("\n--- IP Request Counts ---")
    for ip, count in sorted(analysis_results['ip_requests'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{ip:<15} {count:>5} requests")
    
    print("\n--- Most Accessed Endpoint ---")
    endpoint, count = analysis_results['most_accessed_endpoint']
    print(f"{endpoint} (Accessed {count} times)")
    
    print("\n--- Suspicious Activity ---")
    for ip, count in sorted(analysis_results['suspicious_ips'].items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<15} {count:>3} failed login attempts")

def main():
    log_file_path = 'sample.log'
    analysis_results = parse_log_file(log_file_path)
    
    display_results(analysis_results)
    save_results_to_csv(analysis_results)
    print("\nResults saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()