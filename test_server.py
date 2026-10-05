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
        
        # 3. tools/call - scan_secrets (Safe Scenario)
        safe_secret_payload = "This is a normal public configuration file. No secrets here."
        safe_sec_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "scan_secrets",
                "arguments": {"text": safe_secret_payload}
            }
        }
        safe_sec_res = send_request(proc, safe_sec_req)
        assert safe_sec_res.get("id") == 3
        assert safe_sec_res.get("result", {}).get("isError", False) is False
        safe_sec_findings = json.loads(safe_sec_res.get("result", {}).get("content", [])[0].get("text"))
        assert len(safe_sec_findings) == 0, f"Expected 0 findings, got: {safe_sec_findings}"

        # 4. tools/call - scan_secrets (Unsafe Scenario)
        unsafe_secret_payload = "Token: ghp_1234567890abcdef1234567890abcdef12345678\nEntropy: 8f9b90c2a7147e651e038848d5f306634b22c710"
        unsafe_sec_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "scan_secrets",
                "arguments": {"text": unsafe_secret_payload}
            }
        }
        unsafe_sec_res = send_request(proc, unsafe_sec_req)
        assert unsafe_sec_res.get("id") == 4
        assert unsafe_sec_res.get("result", {}).get("isError", False) is True
        unsafe_sec_findings = json.loads(unsafe_sec_res.get("result", {}).get("content", [])[0].get("text"))
        assert len(unsafe_sec_findings) >= 2, f"Expected >= 2 findings, got: {unsafe_sec_findings}"
        
        # 5. tools/call - check_code_sinks (Safe Scenario)
        safe_code_payload = "def calculate_sum(a, b):\n    return a + b\nprint(calculate_sum(5, 10))"
        safe_code_req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "check_code_sinks",
                "arguments": {"code": safe_code_payload}
            }
        }
        safe_code_res = send_request(proc, safe_code_req)
        assert safe_code_res.get("id") == 5
        assert safe_code_res.get("result", {}).get("isError", False) is False
        safe_code_findings = json.loads(safe_code_res.get("result", {}).get("content", [])[0].get("text"))
        assert len(safe_code_findings) == 0, f"Expected 0 sink findings, got: {safe_code_findings}"

        # 6. tools/call - check_code_sinks (Unsafe Scenario)
        unsafe_code_payload = "import subprocess\nuser_input = 'malicious_shell_command'\neval(user_input)\nsubprocess.Popen('ls', shell=True)"
        unsafe_code_req = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "check_code_sinks",
                "arguments": {"code": unsafe_code_payload}
            }
        }
        unsafe_code_res = send_request(proc, unsafe_code_req)
        assert unsafe_code_res.get("id") == 6
        assert unsafe_code_res.get("result", {}).get("isError", False) is True
        unsafe_code_findings = json.loads(unsafe_code_res.get("result", {}).get("content", [])[0].get("text"))
        assert len(unsafe_code_findings) == 2, f"Expected 2 sink findings, got: {unsafe_code_findings}"
        assert unsafe_code_findings[0]["risk"] == "High"
        assert unsafe_code_findings[1]["risk"] == "Critical"
        
        print("All tests passed successfully.")
        sys.exit(0)
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()
