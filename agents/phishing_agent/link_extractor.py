import re
from urllib.parse import urlparse

def extract_links(email_body: str) -> list:
    """
    Extracts all URLs from the given email body.
    """
    urls = re.findall(r'https?://[^\s"<>]+', email_body)
    return [urlparse(u).geturl() for u in urls]