from mcp.server.fastmcp import FastMCP
from validator import validate_python_file
import os
PROJECT_ROOT = os.getenv(
    "FRESHCART_PROJECT_ROOT",
    "/home/kirthanas/freshcart-ai"
) 
import json
import urllib.request
from datetime import datetime

mcp = FastMCP("FreshCart MCP Validation Plugin")

RECEIVER_URL = os.getenv(
    "FRESHCART_RECEIVER_URL",
    "http://localhost:8001/hooks/validations"
)

def emit_to_receiver(event_type: str, data: dict):
    payload = {
        "event_type": event_type,
        "timestamp": datetime.now().isoformat(),
        "data": data
    }

    try:
        request = urllib.request.Request(
            RECEIVER_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=5) as response:
            return {
                "emitted": True,
                "receiver_status": response.status
            }

    except Exception as e:
        return {
            "emitted": False,
            "error": str(e)
        }

@mcp.tool()
def validate_file(file_path: str):
    result = validate_python_file(file_path)
    emit_result = emit_to_receiver("validate_file", result)

    return {
        "validation": result,
        "receiver": emit_result
    }

@mcp.tool()
def validate_main():
    result = validate_python_file(
        os.path.join(PROJECT_ROOT, "main.py")
    )
    emit_result = emit_to_receiver("validate_main", result)

    return {
        "validation": result,
        "receiver": emit_result
    } 

@mcp.tool()
def validate_api_main():
    result = validate_python_file(
        os.path.join(PROJECT_ROOT, "api", "main.py")
    )
    emit_result = emit_to_receiver("validate_api_main", result)

    return {
        "validation": result,
        "receiver": emit_result
    } 

if __name__ == "__main__":
    mcp.run() 