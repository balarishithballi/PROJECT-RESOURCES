#!/usr/bin/env python3

import os
import re
import json
from datetime import datetime

INPUT_DIR = "./logs"
OUTPUT_FILE = "merged_logs.jsonl"

def normalize_timestamp(raw_ts):
    patterns = [
        ("%b %d %H:%M:%S", False),       
        ("%d/%b/%Y:%H:%M:%S %z", True),  
        ("%Y-%m-%d %H:%M:%S", True),     
        ("%Y-%m-%dT%H:%M:%S.%fZ", True), 
        ("%Y-%m-%dT%H:%M:%SZ", True)
    ]
    for fmt, has_year in patterns:
        try:
            dt = datetime.strptime(raw_ts, fmt)
            if not has_year:
                dt = dt.replace(year=datetime.now().year)
            return dt.isoformat() + "Z"
        except Exception:
            continue
    return None

PATTERNS = {
    "syslog": re.compile(r'^(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s(?P<host>\S+)\s(?P<process>\S+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$'),
    "apache_access": re.compile(r'(?P<src_ip>\d+\.\d+\.\d+\.\d+).*\[(?P<timestamp>[^\]]+)\]\s"(?P<method>\S+)\s(?P<url>\S+).*"\s(?P<status>\d+)'),
    "apache_error": re.compile(r'^(?P<timestamp>\w{3}\s+\d+\s[\d:]+).*\[(?P<level>\w+)\]\s\[(?P<pid>\d+)\]\s(?P<message>.+)$'),
    "firewall": re.compile(r'(?P<timestamp>\w{3}\s+\d+\s[\d:]+).*SRC=(?P<src_ip>\S+)\sDST=(?P<dst_ip>\S+)\s.*PROTO=(?P<proto>\S+)\sSPT=(?P<src_port>\d+)\sDPT=(?P<dst_port>\d+)'),
    "ids": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*?(?P<sig>ET\s\S.*?)\s(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s->\s(?P<dst_ip>\d+\.\d+\.\d+\.\d+)'),
    "proxy": re.compile(r'(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s(?P<host>\S+)\s.*\s(?P<status>\d{3})\s(?P<url>https?://\S+)'),
    "db_query": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*user=(?P<user>\S+).*query="(?P<query>[^"]+)"'),
    "db_transaction": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*tx\[(?P<txn_id>[a-f0-9\-]+)\]:\s(?P<ops>\d+)\sstatements'),
    "cloud_audit": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\sproject=(?P<project>\d+)\suser=(?P<user>\S+)\saction=(?P<action>\S+)'),
    "api_request": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*"(?P<method>\S+)\s(?P<path>\S+)".*status=(?P<status>\d+)'),
    "config_change": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*user=(?P<user>\S+)\schange="(?P<change>[^"]+)"'),
    "role_change": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*actor=(?P<admin>\S+).*role=(?P<role>\S+)'),
    "log_management": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*operation=(?P<op>\S+)\starget=(?P<target>\S+)'),
    "log_archive": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*saved\s(?P<archive>\S+)'),
    "badge_access": re.compile(r'(?P<timestamp>\w{3}\s+\d+\s[\d:]+).*badge=(?P<badge>\S+).*door="(?P<door>[^"]+)"\sresult=(?P<result>\S+)'),
    "environmental": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+).*sensor=(?P<sensor>\S+)\sreading=(?P<value>[\d\.]+)'),
    "usb": re.compile(r'(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s(?P<host>\S+).*usb.*(?P<serial>SN\d+)\s(?P<action>\S+)'),
    "evtx": re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s[\d:]+)\s(?P<type>\S+)\sEventID=(?P<event_id>\d+)\sUser=(?P<user>\S+)')
}

def detect_type(filename):
    name = filename.lower()
    if "apache" in name or "access" in name:
        return "apache_access"
    if "error" in name:
        return "apache_error"
    if "firewall" in name:
        return "firewall"
    if "ids" in name:
        return "ids"
    if "proxy" in name:
        return "proxy"
    if "db_query" in name:
        return "db_query"
    if "db_transaction" in name:
        return "db_transaction"
    if "cloud" in name:
        return "cloud_audit"
    if "api" in name:
        return "api_request"
    if "config_change" in name:
        return "config_change"
    if "role_change" in name:
        return "role_change"
    if "management" in name:
        return "log_management"
    if "archive" in name:
        return "log_archive"
    if "badge" in name:
        return "badge_access"
    if "environmental" in name:
        return "environmental"
    if "usb" in name:
        return "usb"
    if "evtx" in name:
        return "evtx"
    return "syslog"  

def parse_line(line, log_type, fname):
    entry = {"source_file": fname, "raw": line.strip()}
    pattern = PATTERNS.get(log_type)
    if not pattern:
        return entry
    m = pattern.search(line)
    if not m:
        return entry
    data = m.groupdict()
    entry.update(data)
    if "timestamp" in entry:
        entry["timestamp"] = normalize_timestamp(entry["timestamp"])
    entry["event_type"] = log_type
    return entry

def find_log_files(base_dir=INPUT_DIR):
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".log") or f.endswith(".logs"):
                yield os.path.join(root, f)

def unify_all_logs(input_dir=INPUT_DIR, output_file=OUTPUT_FILE):
    count = 0
    with open(output_file, "w", encoding="utf-8") as out:
        for path in find_log_files(input_dir):
            fname = os.path.basename(path)
            log_type = detect_type(fname)
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    parsed = parse_line(line, log_type, fname)
                    json.dump(parsed, out)
                    out.write("\n")
                    count += 1
            print(f"[+] Parsed {fname} ({log_type})")
    print(f"\n✅ Unified {count:,} log entries → {output_file}")

if __name__ == "__main__":
    unify_all_logs()
