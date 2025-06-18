import hashlib

def analyze_attachments(attachments: list) -> list:
    """
    Generates SHA256 hash of each attachment to use with threat intel lookups.
    """
    results = []
    for file in attachments:
        try:
            content = file.get("content", "").encode()
            sha256 = hashlib.sha256(content).hexdigest()
            results.append({
                "filename": file.get("filename", "unknown"),
                "sha256": sha256
            })
        except Exception as e:
            results.append({"filename": file.get("filename", "unknown"), "error": str(e)})
    return results

