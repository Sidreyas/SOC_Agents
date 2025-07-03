import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ACCESS_TOKEN = "your_access_token"
GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0/security/alerts"

def get_phishing_alerts():
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    params = {
        "$filter": "category eq 'Phishing'",
        "$top": 5  
    }

    try:
        response = requests.get(GRAPH_API_ENDPOINT, headers=headers, params=params)
        response.raise_for_status()
        alerts = response.json().get("value", [])
        logger.info(f"Fetched {len(alerts)} phishing alerts.")
        return alerts
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return []
