from typing import Union, Dict
import re

def parse_headers(raw_headers: str) -> Dict[str, Union[str, bool, None]]:
    """
    Basic parser to extract sender IP and SPF/DKIM indicators from raw headers.
    """
    results: Dict[str, Union[str, bool, None]] = {
        "sender_ip": None,
        "spf_pass": None,
        "dkim_pass": None
    }
    try:
        if "Received: from" in raw_headers:
            match = re.search(r"Received: from .*\[(\d+\.\d+\.\d+\.\d+)\]", raw_headers)
            if match:
                results["sender_ip"] = match.group(1)

        if "spf=pass" in raw_headers.lower():
            results["spf_pass"] = True
        if "dkim=pass" in raw_headers.lower():
            results["dkim_pass"] = True
    except Exception as e:
        results["error"] = str(e)  
        
    return results
