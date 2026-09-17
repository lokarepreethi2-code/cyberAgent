import sys
from src.ingestion.log_parser import parse_log_line
from src.reasoning.threat_detector import analyze_logs
from src.execution.action_handler import execute_threat_actions

def run_pipeline():
    print("=== Starting CyberAgent Defense Pipeline ===")
    
    # 1. Ingestion Phase
    raw_logs = [
        '192.168.1.105 - - [13/Sep/2026:14:04:00 +0000] "POST /login HTTP/1.1" 401 532',
        '192.168.1.105 - - [13/Sep/2026:14:04:02 +0000] "POST /login HTTP/1.1" 401 532',
        '192.168.1.105 - - [13/Sep/2026:14:04:05 +0000] "POST /login HTTP/1.1" 401 532',
        '10.0.0.1 - - [13/Sep/2026:14:05:00 +0000] "GET /index.html HTTP/1.1" 200 2340'
    ]
    
    parsed_logs = [parse_log_line(log) for log in raw_logs if parse_log_line(log)]
    print(f"[Ingestion] Parsed {len(parsed_logs)} log entries.")

    # 2. Reasoning Phase
    detected_threats = analyze_logs(parsed_logs)
    print(f"[Reasoning] Identified {len(detected_threats)} potential threats.")

    # 3. Execution Phase
    actions = execute_threat_actions(detected_threats)
    print("=== Pipeline Execution Complete ===")


if __name__ == "__main__":
    run_pipeline()