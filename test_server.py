import json
import subprocess
import sys

def send_request(proc, request):
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("Server closed connection unexpectedly.")
    return json.loads(line)

def main():
    server_path = "server.py"
    proc = subprocess.Popen(
        [sys.executable, server_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    try:
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "sast-validation-client", "version": "1.0.0"}
            }
        }
        init_res = send_request(proc, init_req)
        assert init_res.get("id") == 1
        assert "serverInfo" in init_res.get("result", {})
        
        list_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }
        list_res = send_request(proc, list_req)
        assert list_res.get("id") == 2
        tools = list_res.get("result", {}).get("tools", [])
        assert len(tools) == 2
        
        secret_payload = "Token: ghp_1234567890abcdef1234567890abcdef12345678\nEntropy: 8f9b90c2a7147e651e038848d5f306634b22c710"
        call_req_1 = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "scan_secrets",
                "arguments": {
                    "text": secret_payload
                }
            }
        }
        call_res_1 = send_request(proc, call_req_1)
        assert call_res_1.get("id") == 3
        findings_json_1 = call_res_1.get("result", {}).get("content", [])[0].get("text")
        findings_1 = json.loads(findings_json_1)
        assert len(findings_1) >= 2, f"Expected >= 2 secret findings, got: {findings_1}"
        
        sink_payload = "import subprocess\nuser_input = 'malicious_shell_command'\neval(user_input)\nsubprocess.Popen('ls', shell=True)"
        call_req_2 = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "check_code_sinks",
                "arguments": {
                    "code": sink_payload
                }
            }
        }
        call_res_2 = send_request(proc, call_req_2)
        assert call_res_2.get("id") == 4
        findings_json_2 = call_res_2.get("result", {}).get("content", [])[0].get("text")
        findings_2 = json.loads(findings_json_2)
        assert len(findings_2) == 2, f"Expected 2 sink findings, got: {findings_2}"
        assert findings_2[0]["risk"] == "High"
        assert findings_2[1]["risk"] == "Critical"
        
        print("All tests passed successfully.")
        sys.exit(0)
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()
