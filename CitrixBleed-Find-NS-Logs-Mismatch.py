# Created by Lucas Silva
# In order to run it you need to have Python 3 installed in your machine and edit the path to the ns-log files on line 31.
# This script will find the mismatch between the Client_ip and Source fields in the ns.log files.
# Reference: https://www.mandiant.com/resources/blog/session-hijacking-citrix-cve-2023-4966

import re
import glob

def extract_ip_address(log_entry, key):
    # Extracts the IP address associated with the given key from a log entry
    match = re.search(fr'{key} (\d+\.\d+\.\d+\.\d+)', log_entry)
    if match:
        return match.group(1)
    return None

def process_log_file(log_file_path):
    with open(log_file_path, 'r') as file:
        for line in file:
            # Assuming each log entry is on a new line
            log_entry = line.strip()

            # Extract IP addresses for "Client_ip" and "Source"
            client_ip = extract_ip_address(log_entry, 'Client_ip')
            source_ip = extract_ip_address(log_entry, 'Source')

            # Compare and print the result
            if client_ip and source_ip and client_ip != source_ip:
                print(f"[!] Mismatch found in {log_file_path}: Client_ip={client_ip}, Source={source_ip}")
            elif client_ip and source_ip and client_ip == source_ip:
                print(f"Match found in {log_file_path}: Client_ip={client_ip}, Source={source_ip}")
def main():
    # Use glob to match files based on the provided pattern
    log_files = glob.glob('ns.log_*.0')

    # Process each log file
    for log_file_path in log_files:
        process_log_file(log_file_path)

if __name__ == "__main__":
    main()