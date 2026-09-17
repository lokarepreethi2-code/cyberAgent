# src/api/main_api.py
from fastapi import FastAPI
from pydantic import BaseModel
from src.ingestion.log_parser import parse_log_line  # Adjust import path if different
from src.reasoning.threat_detector import analyze_logs

app = FastAPI(title="CyberAgent Security API", version="1.0")

class LogPayload(BaseModel):
    log_line: str

@app.post("/analyze")
def analyze_log(payload: LogPayload):
    # 1. Parse the log line
    parsed = parse_log_line(payload.log_line)
    
    # Ensure the raw line is included so threat_detector can scan keywords!
    if isinstance(parsed, dict):
        parsed['raw'] = payload.log_line
        logs_to_analyze = [parsed]
    else:
        logs_to_analyze = []

    # 2. Run threat analysis
    threats = analyze_logs(logs_to_analyze)

    # 3. Extract actions taken
    actions = [t.get("action") for t in threats if "action" in t]

    return {
        "parsed_log": parsed,
        "threats_detected": threats,
        "actions_taken": actions
    }