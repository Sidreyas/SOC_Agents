import requests
import logging

def lookup_with_defender_ti(indicator: str, indicator_type: str, api_key: str) -> dict:
    """
    Queries Microsoft Defender Threat Intelligence API to check URL, IP, or file hash.
    """
    url = f"https://api.security.microsoft.com/tiIndicators/query"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "indicatorValue": indicator,
        "indicatorType": indicator_type
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()
        logging.info(f"[TI Lookup] {indicator_type} {indicator} result: {result}")
        return result
    except Exception as e:
        logging.error(f"[TI Lookup] Error: {e}")
        return {"error": str(e)}
