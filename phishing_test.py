import csv
from phishing_graph import phishing_email_graph
from agents.phishing_agent import logger

logger.setup_logger()

def read_emails_from_csv(file_path):
    emails = []
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            email = {
                "id": row["id"],
                "subject": row["subject"],
                "sender": row["sender"],
                "body": row["body"],
                "raw_headers": row["raw_headers"],
                "attachments": [{"filename": row["attachments"]}],
                "links": [row["links"]]
            }
            emails.append(email)
    return emails

emails = read_emails_from_csv("mock_emails.csv")

for email in emails:
    print(f"\n📩 Processing Email ID: {email['id']} | Subject: {email['subject']}")
    state = {"email": email}
    result = phishing_email_graph.invoke(state)
    # If email was invalid, skip
    if not result.get("valid", True):
        print("⚠️ Skipped: Missing required fields.\n")
        continue
    classification = result.get("llm_result", {}).get("classification", "Unknown")
    reason = result.get("llm_result", {}).get("reason", "No explanation.")
    severity = result.get("severity", "N/A")
    verdict = result.get("verdict", "Unknown")
    verdict_icon = (
        "✅" if severity != "N/A" and severity < 40 else
        "❌" if severity != "N/A" and severity >= 70 else
        "❓"
    )
    if verdict == "Unknown":
        print(f"🔍 Analyst Review Needed (Score: {severity}%) ❓")
        print("The email could not be conclusively classified by the agent.")
        print(f" Reason: {reason}")
        print("👉 Please review the body, sender reputation, and any unusual links or attachments manually.")
    print(f"LLM Verdict: {classification}")
    print(f"Reason: {reason}")
    print(f"Severity Score: {severity}%")
    print(f"Final Verdict: {verdict} {verdict_icon}")
