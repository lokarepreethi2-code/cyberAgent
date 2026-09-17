import re

def parse_log_line(line):
    """
    Parses a single line of security log text to extract IP, timestamp, and status code.
    """
    # Pattern to match IP address, timestamp, and HTTP status code
    log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] ".*?" (?P<status>\d+)'
    
    match = re.search(log_pattern, line)
    if match:
        return match.groupdict()
    return None

def parse_log_file(file_path):
    """
    Reads a log file and returns a list of parsed security entries.
    """
    parsed_logs = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                parsed = parse_log_line(line)
                if parsed:
                    parsed_logs.append(parsed)
    except FileNotFoundError:
        print(f"Error: Log file at {file_path} not found.")
    
    return parsed_logs

if __name__ == "__main__":
    # Test sample log entry
    sample_log = '192.168.1.105 - - [13/Sep/2026:14:04:00 +0000] "GET /admin/login HTTP/1.1" 401'
    result = parse_log_line(sample_log)
    print("Parsed Sample Log:", result)