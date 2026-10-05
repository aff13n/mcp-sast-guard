import sys
import json
import logging
import traceback
from detectors.secrets import scan_secrets
from detectors.sinks import check_code_sinks

logging.basicConfig(
    filename='sast_guard.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def send_response(response: dict):
    print(json.dumps(response), flush=True)

def handle_message(message: dict):
    msg_id = message.get("id")
    method = message.get("method")
    params = message.get("params", {})

    if method == "initialize":
        send_response({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "mcp-sast-guard",
                    "version": "1.0.0"
                }
            }
        })
    elif method == "tools/list":
        send_response({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "scan_secrets",
                        "description": "Scan text for secrets and high entropy strings",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {
                                    "type": "string",
                                    "description": "Text to scan"
                                }
                            },
                            "required": ["text"]
                        }
                    },
                    {
                        "name": "check_code_sinks",
                        "description": "Check Python code for dangerous patterns like eval and shell=True",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "description": "Python code to analyze"
                                }
                            },
                            "required": ["code"]
                        }
                    }
                ]
            }
        })
    elif method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})
        
        try:
            is_blocked = False
            if tool_name == "scan_secrets":
                text = args.get("text", "")
                findings = scan_secrets(text)
                if findings:
                    logging.warning(f"Blocked unsafe text payload. Secrets found: {json.dumps(findings)}")
                    is_blocked = True
                result_content = json.dumps(findings)
            elif tool_name == "check_code_sinks":
                code = args.get("code", "")
                findings = check_code_sinks(code)
                if findings:
                    logging.warning(f"Blocked unsafe code payload. Sinks found: {json.dumps(findings)}")
                    is_blocked = True
                result_content = json.dumps(findings)
            else:
                send_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": "Method not found"
                    }
                })
                return

            send_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": is_blocked,
                    "content": [
                        {
                            "type": "text",
                            "text": result_content
                        }
                    ]
                }
            })
        except Exception as e:
            send_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": str(e)
                }
            })

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
            handle_message(message)
        except json.JSONDecodeError:
            send_response({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32700,
                    "message": "Parse error"
                }
            })

if __name__ == "__main__":
    main()
