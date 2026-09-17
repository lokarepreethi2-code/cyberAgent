
# AI-powered Autonomous Cybersecurity Incident Response and Threat Mitigation Agent (CyberAgent)

CyberAgent is a lightweight, real-time security ingestion and threat detection engine built with FastAPI. It parses raw system and server logs to detect security threats (such as Path Traversal attacks) and returns structured analysis for automated incident response.

## Key Features
- **Log Ingestion & Parsing:** Extracts structured fields from raw HTTP and server log strings.
- **Threat Detection Engine:** Scans parsed log payloads for malicious signatures and attack patterns.
- **FastAPI Endpoints:** Interactive API documentation via Swagger UI for testing and integration.

## Project Structure
```text
cyberAgent/
├── src/
│   ├── api/             # FastAPI application and endpoint definitions
│   ├── ingestion/       # Log parsing logic
│   ├── reasoning/       # Threat detection logic
│   └── execution/       # Action handlers and response routines
├── main.py              # Application entry point
└── requirements.txt     # Dependency specifications
