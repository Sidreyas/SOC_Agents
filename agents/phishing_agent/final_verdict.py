
def make_final_verdict(indicators: dict, ml_verdict: str) -> str:
    """
    Combine rule-based indicators and ML verdict into final classification.
    """
    if indicators.get("malicious_links") or indicators.get("bad_hashes"):
        return "phishing"
    elif ml_verdict == "phishing":
        return "phishing"
    return "clean"
