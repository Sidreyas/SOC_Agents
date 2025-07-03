from state import AgentState
import base64
import logging
import re

logger = logging.getLogger("AgentLogger")

def decode_base64_string(encoded: str) -> str:
    try:
        return base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return "[DecodeError]"

def script_decoder_node(state: AgentState) -> AgentState:
    logger.info("🧩 [Step 2] Decoding PowerShell script...")
    raw_cmd = state.alert_data.get("script", "")

    decoded = ""
    match = re.search(r'EncodedCommand\s+([A-Za-z0-9+/=]+)', raw_cmd)
    if match:
        encoded = match.group(1)
        decoded = decode_base64_string(encoded)
    else:
        decoded = raw_cmd  # assume plain text

    logger.info(f"Decoded script: {decoded[:100]}...")
    state.decoded_script = decoded
    state.logs.append("[2] PowerShell script decoded.")
    return state
