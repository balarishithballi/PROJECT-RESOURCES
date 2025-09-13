import re
import csv
import glob
import os
from datetime import datetime

# Define regex signature patterns for auto detection of the log format
LOG_SIGNATURES = {
    'apache': re.compile(r'^\[[\w\s:/]+\] \[.*\]'),        # e.g. [Sun Dec 04 04:47:44 2005] [error]
    'linux_syslog': re.compile(r'^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2} [\w\-]+ '),  # e.g. Jun 14 15:16:01 hostname ...
    'mixed_access': re.compile(r'^\d{1,3}(\.\d{1,3}){3} - '),  # e.g. 240.104.101.92 - user [date] "GET ...
    'openssh': re.compile(r'^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2} .+ sshd\['), # e.g. Dec 10 06:55:46 hostname sshd[pid]:
    'openstack': re.compile(r'^\w+-api\.log\.\d'),         # e.g. nova-api.log.1.2017-05-16_13:53:08 ...
    'windows_cbs': re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}, Info\s+CBS'),  # CBS logs timestamp format
    'firewall': re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+ '), # Firewall logs ISO8601 style
}

# Define parsers for each log type
def parse_apache(line):
    # Sample: [Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6
    regex = re.compile(r'\[(?P<timestamp>[^\]]+)\] \[(?P<level>[^\]]+)\] (?P<message>.+)')
    m = regex.match(line)
    if m:
        return {
            'timestamp': m.group('timestamp'),
            'log_level': m.group('level'),
            'source': 'apache',
            'user': None,
            'src_ip': None,
            'dst_ip': None,
            'message': m.group('message')
        }
    return None

def parse_linux_syslog(line):
    # Sample: Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 
    regex = re.compile(r'^(?P<timestamp>[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>[\w\-\._]+) (?P<process>[^\[]+)\[\d+\]: (?P<message>.+)')
    m = regex.match(line)
    if m:
        # Extract IP from message rhost if present
        rhost_match = re.search(r'rhost=([\d\.]+)', m.group('message'))
        user_match = re.search(r'user=([\w\-]+)', m.group('message'))
        return {
            'timestamp': m.group('timestamp'),
            'log_level': None,
            'source': 'linux_syslog',
            'user': user_match.group(1) if user_match else None,
            'src_ip': rhost_match.group(1) if rhost_match else None,
            'dst_ip': None,
            'message': m.group('message')
        }
    return None

def parse_mixed_access(line):
    # Sample: 240.104.101.92 - adams3352 [13/Sep/2025:16:35:51 +0530] "DELETE /enhance/harness/mesh HTTP/2.0" 400 ...
    regex = re.compile(r'^(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}) - (?P<user>[\w\d\-]+|-) \[(?P<timestamp>[^\]]+)\] "(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD) (?P<request>[^\s]+) HTTP/[^\"]+" (?P<status>\d{3}) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"')
    m = regex.match(line)
    if m:
        return {
            'timestamp': m.group('timestamp'),
            'log_level': None,
            'source': 'mixed_access',
            'user': m.group('user') if m.group('user') != '-' else None,
            'src_ip': m.group('src_ip'),
            'dst_ip': None,
            'message': f"{m.group('method')} {m.group('request')} Status:{m.group('status')}"
        }
    return None

def parse_openssh(line):
    # Sample: Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
    regex = re.compile(r'^(?P<timestamp>[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>[\w\-\._]+) sshd\[\d+\]: (?P<message>.+)')
    m = regex.match(line)
    if m:
        ip_match = re.search(r'from ([\d\.]+)', m.group('message'))
        user_match = re.search(r'user ([\w\-]+)', m.group('message'))
        invalid_user_match = re.search(r'invalid user ([\w\-]+)', m.group('message'))
        user_name = user_match.group(1) if user_match else (invalid_user_match.group(1) if invalid_user_match else None)
        return {
            'timestamp': m.group('timestamp'),
            'log_level': None,
            'source': 'openssh',
            'user': user_name,
            'src_ip': ip_match.group(1) if ip_match else None,
            'dst_ip': None,
            'message': m.group('message')
        }
    return None

def parse_openstack(line):
    # Sample: nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO nova.osapi_compute.wsgi.server [req...] ...
    regex = re.compile(r'^nova-\w+\.log\.\d+\.\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2} (?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) (?P<pid>\d+) (?P<level>\w+) (?P<component>\S+) \[(?P<req>[^\]]+)\] (?P<message>.+)')
    m = regex.match(line)
    if m:
        return {
            'timestamp': m.group('timestamp'),
            'log_level': m.group('level'),
            'source': 'openstack',
            'user': None,
            'src_ip': None,
            'dst_ip': None,
            'message': m.group('message')
        }
    return None

def parse_windows_cbs(line):
    # Sample: 2016-09-28 04:30:30, Info                  CBS    Loaded Servicing Stack v6.1.7601.23505 with Core: ...
    regex = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), (?P<level>\w+)\s+CBS\s+(?P<message>.+)')
    m = regex.match(line)
    if m:
        return {
            'timestamp': m.group('timestamp'),
            'log_level': m.group('level'),
            'source': 'windows_cbs',
            'user': None,
            'src_ip': None,
            'dst_ip': None,
            'message': m.group('message')
        }
    return None

def parse_firewall(line):
    # Sample: 2025-09-13T16:39:28.600146 IN=eth14 OUT=eth8 SRC=161.47.173.125 DST=34.227.7.174 ...
    regex = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) IN=[^\s]+ OUT=[^\s]+ [^=]+=(?P<src_ip>[\d\.]+) DST=(?P<dst_ip>[\d\.]+) (?P<rest>.+)$')
    m = regex.match(line)
    if m:
        return {
            'timestamp': m.group('timestamp'),
            'log_level': None,
            'source': 'firewall',
            'user': None,
            'src_ip': m.group('src_ip'),
            'dst_ip': m.group('dst_ip'),
            'message': m.group('rest')
        }
    return None

# Map log type to parser function
PARSERS = {
    'apache': parse_apache,
    'linux_syslog': parse_linux_syslog,
    'mixed_access': parse_mixed_access,
    'openssh': parse_openssh,
    'openstack': parse_openstack,
    'windows_cbs': parse_windows_cbs,
    'firewall': parse_firewall,
}

# Define common CSV headers for normalized output
CSV_HEADERS = ['timestamp', 'log_level', 'source', 'user', 'src_ip', 'dst_ip', 'message']

def detect_log_type(line):
    for log_type, pattern in LOG_SIGNATURES.items():
        if pattern.match(line):
            return log_type
    return None

def normalize_timestamp(ts_str, log_type):
    # Normalize timestamps to ISO8601 string if possible
    try:
        if log_type == 'apache':
            # Example: Sun Dec 04 04:47:44 2005 -> 2005-12-04T04:47:44
            dt = datetime.strptime(ts_str, '%a %b %d %H:%M:%S %Y')
        elif log_type in ['linux_syslog', 'openssh']:
            # Example: Jun 14 15:16:01 -> use current year or specify year if known
            current_year = datetime.now().year
            dt = datetime.strptime(f'{current_year} {ts_str}', '%Y %b %d %H:%M:%S')
        elif log_type == 'mixed_access':
            # Example: 13/Sep/2025:16:35:51 +0530 -> parse ignoring timezone offset here
            dt = datetime.strptime(ts_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        elif log_type == 'openstack':
            # Example: 2017-05-16 00:00:00.008
            dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S.%f')
        elif log_type == 'windows_cbs':
            # Example: 2016-09-28 04:30:30
            dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
        elif log_type == 'firewall':
            # Example: 2025-09-13T16:39:28.600146
            dt = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S.%f')
        else:
            dt = None
        return dt.isoformat() if dt else ts_str
    except Exception:
        return ts_str

def parse_log_line(line):
    log_type = detect_log_type(line)
    if not log_type:
        return None
    parse_func = PARSERS.get(log_type)
    if not parse_func:
        return None
    parsed = parse_func(line)
    if not parsed:
        return None
    parsed['timestamp'] = normalize_timestamp(parsed['timestamp'], log_type)
    # Replace None with ''
    for k in CSV_HEADERS:
        if parsed.get(k) is None:
            parsed[k] = ''
    return parsed

def parse_log_file(input_path, output_csv_path):
    """Parse a single log file and write to CSV"""
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as infile, \
         open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for line in infile:
            line = line.strip()
            if not line:
                continue
            parsed = parse_log_line(line)
            if parsed:
                writer.writerow(parsed)

def parse_all_log_files(log_dir, output_csv_path):
    """Parse all .log files in a directory and write to a single CSV"""
    log_files = glob.glob(os.path.join(log_dir, "*.log"))
    
    if not log_files:
        print(f"No .log files found in directory: {log_dir}")
        return
    
    print(f"Found {len(log_files)} .log files to process:")
    for log_file in log_files:
        print(f"  - {os.path.basename(log_file)}")
    
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        writer.writeheader()
        
        total_processed = 0
        total_parsed = 0
        
        for log_file in log_files:
            print(f"Processing: {os.path.basename(log_file)}")
            file_processed = 0
            file_parsed = 0
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as infile:
                for line in infile:
                    line = line.strip()
                    if not line:
                        continue
                    file_processed += 1
                    parsed = parse_log_line(line)
                    if parsed:
                        writer.writerow(parsed)
                        file_parsed += 1
            
            print(f"  - Processed {file_processed} lines, parsed {file_parsed} entries")
            total_processed += file_processed
            total_parsed += file_parsed
        
        print(f"\nSummary:")
        print(f"Total lines processed: {total_processed}")
        print(f"Total entries parsed: {total_parsed}")
        print(f"Output written to: {output_csv_path}")

if __name__ == "__main__":
    parse_all_log_files(".", "output.csv")

