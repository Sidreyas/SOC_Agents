def classify_email_with_ml(email_data: dict) -> str:
    """
    Stub ML function that classifies email.
    Replace with actual model call or sandbox submission logic.
    """
    # Placeholder logic for demo
    subject = email_data.get("subject", "").lower()
    if "invoice" in subject and "zip" in str(email_data.get("attachments")):
        return "phishing"
    return "clean"

