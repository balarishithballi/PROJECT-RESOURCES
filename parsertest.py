#!/usr/bin/env python3
"""
log_parser.py
Auto-detects and parses all *.log files in the specified inputs into a CSV,
including Apache, Linux, OpenSSH, OpenStack, Windows, and Apache Combined Log Format.
"""
import re
import argparse
import glob
import os
import csv

# Regex patterns to detect log type by first line
DETECT_PATTERNS = {
    'apache': re.compile(r'^\[.*\]\s+\[\w+\]\s+'),
    'linux': re.compile(r'^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\[\d+\]:'),
    'openssh': re.compile(r'^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd\['),
    'openstack': re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+'),
    'windows': re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},'),
    'apache_clf': re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] ".+" \d+ \d+'),
}

# Parsing regex patterns for each log type
PATTERNS = {
    'apache': re.compile(r'^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>\w+)\]\s+(?P<message>.+)$'),
    'linux': re.compile(r'^(?P<date>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>[\w\-/]+)\[\d+\]:\s+(?P<message>.+)$'),
    'openssh': re.compile(r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+(?P<message>.+)$'),
    'openstack': re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<pid>\d+)\s+(?P<level>\w+)\s+(?P<module>[^\[]+)\[(?P<req>[^\]]*)\]\s+(?P<message>.+)$'),
    'windows': re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s+(?P<level>\w+)\s+(?P<source>\w+)\s+(?P<message>.+)$'),
    'apache_clf': re.compile(
        r'^(?P<ip>\S+) (?P<identity>\S+) (?P<userid>\S+) \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\d+)'
        r'( "(?P<referer>[^"]*)" "(?P<useragent>[^"]*)")?'
    ),
}

def detect_log_type(path):
    """Read first non-empty line to detect log type."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            for lt, pat in DETECT_PATTERNS.items():
                if pat.match(line):
                    return lt
            # Fallback: if line looks like apache clf, return that
            if re.match(r'^\S+ \S+ \S+ \[[^\]]+\] ".+" \d+ \d+', line):
                return 'apache_clf' 
            break
    return None

def parse_line(line, log_type):
    """Parse a single line using the pattern for log_type."""
    pat = PATTERNS.get(log_type)
    if not pat:
        return None
    m = pat.match(line)
    return m.groupdict() if m else None

def parse_file(path, log_type, records, fieldnames_set):
    """Parse entire file, append records, and collect all fieldnames."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            raw = raw.rstrip('\n')
            rec = parse_line(raw, log_type)
            if rec:
                rec['source_file'] = os.path.basename(path)
                records.append(rec)
                fieldnames_set.update(rec.keys())

def main():
    parser = argparse.ArgumentParser(description="Auto-parse all '*.log' files to CSV")
    parser.add_argument('-o', '--output', required=True, help='Output CSV filename')
    parser.add_argument('inputs', nargs='*', default=['*.log'], help='Input log files or glob patterns')
    args = parser.parse_args()

    # Collect files from inputs and globs
    files = []
    for inp in args.inputs:
        files.extend(glob.glob(inp))
    files = sorted(set(files))

    records = []
    fieldnames_set = set()
    for filepath in files:
        lt = detect_log_type(filepath)
        if lt:
            parse_file(filepath, lt, records, fieldnames_set)
        else:
            print(f"Warning: Could not detect log type for '{filepath}', skipping.", flush=True)

    fieldnames = ['source_file'] + sorted(fn for fn in fieldnames_set if fn != 'source_file')
    with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)

if __name__ == '__main__':
    main()
