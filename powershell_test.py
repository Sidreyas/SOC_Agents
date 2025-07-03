from agents.powershell_agent import (
    ingest_alerts,
    validate_alert,
    extract_entities,
    powershell_pattern,
    exploit_classifier,
    threat_intel_lookup,
    risk_scorer,
    final_decision,
    remediation,
    logger
)

logger.setup_logger()

mock_alert = {
    "id": "ps-001",
    "title": "Suspicious PowerShell execution",
    "hostName": "HOST-001",
    "userPrincipalName": "attacker@company.com",
    "commandLine": "powershell.exe -enc JABlAHgAcABsAG8AaQB0AC0AagBi",
    "fileHash": "bad1234567890",
    "timestamp": "2025-06-17T08:45:00Z"
}

# Step 1 - Normalize and validate
alert = ingest_alerts.ingest_alert(mock_alert)
if not validate_alert.validate_alert(alert):
    print("❌ Invalid alert. Skipping.")
else:
    entities = extract_entities.extract_entities(alert)
    suspicious_cmd = powershell_pattern.is_suspicious_command(entities["command"])
    exploit_type = exploit_classifier.classify_exploit(entities["command"])
    hash_status = threat_intel_lookup.lookup_hash_defender_ti(entities["hash"])
    score = risk_scorer.calculate_risk_score(suspicious_cmd, exploit_type, hash_status)
    verdict = final_decision.make_decision(score)

    print(f"\n🔍 Risk Score: {score}")
    print(f"🔎 Verdict: {verdict.upper()}")

    remediation.take_action(alert["id"], verdict)
