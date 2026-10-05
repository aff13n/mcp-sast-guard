import ast
from typing import List, Dict, Any

class SinkVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def visit_Call(self, node: ast.Call):
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ('eval', 'exec'):
            self.findings.append({
                "line": getattr(node, 'lineno', 0),
                "risk": "High",
                "description": f"Dangerous use of {func_name}() detected"
            })
        
        if func_name in ('Popen', 'call', 'run'):
            for keyword in node.keywords:
                if keyword.arg == 'shell':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        self.findings.append({
                            "line": getattr(node, 'lineno', 0),
                            "risk": "Critical",
                            "description": "subprocess call with shell=True detected"
                        })
        self.generic_visit(node)

def check_code_sinks(code_str: str) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(code_str)
    except SyntaxError:
        return []
    
    visitor = SinkVisitor()
    visitor.visit(tree)
    return visitor.findings
