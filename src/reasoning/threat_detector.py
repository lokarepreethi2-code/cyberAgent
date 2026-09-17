def analyze_logs(parsed_logs, failed_threshold=3):
    failed_attempts = {}
    threats = []

    for log in parsed_logs:
        ip = log.get('ip', 'Unknown')
        raw_log = log.get('raw', '')
        status = log.get('status', '')

        # 1. Rule-Based Signature Detection
        if "/etc/passwd" in raw_log or "../" in raw_log:
            threats.append({
                "ip": ip,
                "threat_type": "Path Traversal",
                "threat_level": "HIGH",
                "action": "FLAG_SUSPICIOUS_IP"
            })
        elif "SELECT" in raw_log.upper() or "UNION" in raw_log.upper() or "'" in raw_log:
            threats.append({
                "ip": ip,
                "threat_type": "SQL Injection",
                "threat_level": "CRITICAL",
                "action": "BLOCK_IP"
            })

        # 2. Behavioral Tracking (Failed Logins)
        if status == '401':
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # Check brute-force thresholds
    for ip, count in failed_attempts.items():
        if count >= failed_threshold:
            threats.append({
                "ip": ip,
                "threat_type": "Brute Force Attack",
                "failed_count": count,
                "threat_level": "HIGH",
                "action": "BLOCK_IP"
            })

    return threats