import os
import requests
import json
import re


def setup_logger():
    import logging
    logger = logging.getLogger('phishing_agent')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = "deepseek-r1-distill-llama-70b"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

def classify_email_with_llm(email):
    prompt = f"""
You are a security analyst. Given the following email, classify it as either 'Phishing' or 'Legitimate' and explain why.

Subject: {email.get('subject', '')}

From: {email.get('from', '')}

Body:
{email.get('body', '')}

Respond in JSON format like:
{{
    "classification": "Phishing",
    "reason": "The email contains suspicious links and impersonates a trusted brand."
}}
    """

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    response = None
    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        logger.info(f"Raw API response: {response.text}")

        # Extract the content field
        reply = response.json()["choices"][0]["message"]["content"]

        # Use regex to extract the JSON block
        match = re.search(r"```json\n(.*?)\n```", reply, re.DOTALL)
        if match:
            json_block = match.group(1)
            return json.loads(json_block)
        else:
            raise ValueError("No JSON block found in the response content.")

    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error: {e}")
        if response:
            logger.error(f"Response content: {response.text}")
        return {
            "classification": "Unknown",
            "reason": "HTTP error or invalid response"
        }
    except json.JSONDecodeError as e:
        logger.error(f"JSON decoding failed: {e}")
        logger.error(f"Raw response: {response.text if response else 'No response'}")
        return {
            "classification": "Unknown",
            "reason": "Invalid JSON response"
        }
    except Exception as e:
        logger.error(f"LLM classification failed: {e}")
        return {
            "classification": "Unknown",
            "reason": "LLM error or insufficient data"
        }