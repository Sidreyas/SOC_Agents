def validate_email(email: dict) -> bool:
    """
    Validates whether the ingested email has all necessary fields for analysis.
    """
    required_fields = ["subject", "sender", "raw_headers"]
    if not email:
        return False
    for field in required_fields:
        if not email.get(field):
            return False
    return True

