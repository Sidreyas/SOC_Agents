import logging

def ingest_email(sentinel_alert: dict) -> dict:
    """
    Extracts relevant email information from a Microsoft Sentinel alert.
    Assumes alert format includes extendedProperties or Entities with email content.
    """
    try:
        email_data = {
            "id": sentinel_alert.get("id"),
            "subject": sentinel_alert.get("properties", {}).get("Title"),
            "sender": sentinel_alert.get("entities", [{}])[0].get("address", ""),
            "raw_headers": sentinel_alert.get("entities", [{}])[0].get("Header", ""),
            "attachments": sentinel_alert.get("entities", [{}])[0].get("Attachments", []),
            "links": sentinel_alert.get("entities", [{}])[0].get("Links", [])
        }
        logging.info(f"[Email Ingest] Extracted email: {email_data['subject']} from sender {email_data['sender']}")
        return email_data
    except Exception as e:
        logging.error(f"[Email Ingest] Failed to parse email: {e}")
        return {}