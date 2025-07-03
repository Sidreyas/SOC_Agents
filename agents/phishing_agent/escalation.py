import logging

def escalate_or_close(email_id: str, verdict: str):
    """
    Mock function to simulate escalation or closure.
    """
    if verdict == "phishing":
        logging.info(f"[Escalation] Email ID {email_id} marked as PHISHING and Updated in Sentinel.")
    else:
        logging.info(f"[Escalation] Email ID {email_id} marked as CLEAN and closed.")
