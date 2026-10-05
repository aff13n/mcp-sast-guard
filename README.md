# MCP SAST Guard

MCP SAST Guard (`mcp-sast-guard`) is a Model Context Protocol (MCP) server designed to provide integrated Static Application Security Testing (SAST) capabilities. It exposes security analysis tools that language models and MCP clients can leverage to detect exposed secrets and dangerous code execution sinks in real-time.

Built entirely on the Python 3 standard library, `mcp-sast-guard` introduces zero external dependencies and operates over standard I/O via JSON-RPC 2.0.

## Core Capabilities

The server provides specialized security detectors:

1. **Secret & Credential Detection**
   - High-entropy string analysis (Shannon entropy > 4.5 for strings >= 32 characters)
   - Precise regex matching for critical token patterns (e.g., GitHub tokens, private RSA keys, and generic API credentials).

2. **Dangerous Sink Analysis**
   - Abstract Syntax Tree (AST) parsing of Python source code to detect high-risk structural patterns.
   - Identifies unchecked evaluations (`eval`, `exec`).
   - Flags critical severity subprocess vulnerabilities (e.g., `subprocess.Popen` with `shell=True`).

## Architecture

```text
mcp-sast-guard/
├── detectors/
│   ├── secrets.py       # Entropy algorithms and credential heuristics
│   └── sinks.py         # AST node visitation for sink detection
├── server.py            # Primary MCP stdio server implementation 
└── test_server.py       # Integration suite simulating an MCP client
```

## Available MCP Tools

### `scan_secrets`
Analyzes raw text to identify embedded credentials or abnormally high-entropy strings.
- **Input Schema:** `{"type": "object", "properties": {"text": {"type": "string", "description": "Text to scan"}}}`
- **Output:** JSON array containing detection dictionaries (`type`, `line`, `preview`).

### `check_code_sinks`
Parses and evaluates Python source code against a matrix of dangerous execution sinks.
- **Input Schema:** `{"type": "object", "properties": {"code": {"type": "string", "description": "Python code to analyze"}}}`
- **Output:** JSON array containing vulnerability findings (`line`, `risk`, `description`).

## Installation

No `pip` installation or virtual environment is required. Requires Python 3.8+.

```bash
cd mcp-sast-guard
```

## Usage

MCP servers operate over standard input and output streams. To integrate `mcp-sast-guard` into an MCP-compatible client, configure the client to execute the server script:

```json
{
  "mcpServers": {
    "sast-guard": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp-sast-guard/server.py"]
    }
  }
}
```

## Testing

An automated integration suite is provided to validate the JSON-RPC interface and ensure detector reliability against known vulnerable payloads.

Execute the test client:

```bash
python3 test_server.py
```

If successful, the script terminates with exit code `0` and outputs:
```text
All tests passed successfully.
```
