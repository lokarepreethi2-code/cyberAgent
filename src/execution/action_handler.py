def execute_threat_actions(threats):
    """
    Takes a list of detected threats and simulates defensive execution steps.
    """
    actions_taken = []
    
    if not threats:
        print("No threats detected. System normal.")
        return actions_taken

    for threat in threats:
        ip = threat.get("ip")
        action = threat.get("action")
        
        if action == "BLOCK_IP":
            status_msg = f"[ACTION TAKEN] IP {ip} has been successfully BLOCKED in firewall."
            print(status_msg)
            actions_taken.append({"ip": ip, "status": "BLOCKED"})
            
    return actions_taken

if __name__ == "__main__":
    # Test sample threat list
    sample_threats = [{
        "ip": "192.168.1.105",
        "failed_count": 3,
        "threat_level": "HIGH",
        "action": "BLOCK_IP"
    }]
    
    execute_threat_actions(sample_threats)