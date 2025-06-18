from agents.phishing_agent import (
    email_ingest,
    validate_email,
    header_parser,
    link_extractor,
    attachment_analyzer,
    microsoft_ti_lookup,
    ml_sandbox,
    final_verdict,
    escalation,
    logger
)

# Step 1: Setup logging
logger.setup_logger()

# Step 2: Mock alert input from Sentinel
mock_alert = {
    "id": "email-001",
    "properties": {
        "Title": "URGENT: Please review invoice"
    },
    "entities": [{
        "address": "attacker@example.com",
        "Header": "Received: from mail[192.168.1.10] spf=pass dkim=pass",
        "Attachments": [{"filename": "invoice.zip", "content": "maliciouscontent"}],
        "Links": ["http://bad-url.com"]
    }]
}

# Step 3: Run pipeline
email = email_ingest.ingest_email(mock_alert)
if not validate_email.validate_email(email):
    print("Invalid email.")
    exit()

headers = header_parser.parse_headers(email["raw_headers"])
links = link_extractor.extract_links("Click here: http://bad-url.com")
attachments = attachment_analyzer.analyze_attachments(email["attachments"])

# Combine threat indicators
ti_results = {
    "malicious_links": "bad-url.com" in links,
    "bad_hashes": len(attachments) > 0 and "sha256" in attachments[0]
}

ml_result = ml_sandbox.classify_email_with_ml(email)
verdict = final_verdict.make_final_verdict(ti_results, ml_result)

escalation.escalate_or_close(email["id"], verdict)
