from pathlib import Path
import ast
import re

PROJECT_ROOT = Path("/home/kirthanas/freshcart-ai")

DANGEROUS_COMMANDS = [
    "rm -rf", "rm -f /", "DROP TABLE", "DROP DATABASE",
    "DELETE FROM", "mkfs", "dd if=", "> /dev/",
    "chmod 777", "curl | bash", "wget | bash",
    ":(){:|:&};:", "git push --force", "git push -f",
    "truncate --size 0", "shred", "sudo rm", "sudo dd",
]

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production",
    "secrets.py", "credentials.py",
    ".pem", ".key", ".p12", "id_rsa",
]

DANGEROUS_IMPORTS = [
    "os.system", "subprocess.call", "subprocess.Popen",
    "eval(", "exec(", "__import__",
    "pickle.loads", "marshal.loads",
]

SECRET_PATTERNS = [
    r'sk-ant-[a-zA-Z0-9]+',
    r'sk-[a-zA-Z0-9]{20,}',
    r'password\s*=\s*["\'][^"\']+',
    r'api_key\s*=\s*["\'][^"\']+',
    r'secret\s*=\s*["\'][^"\']+',
    r'AWS_SECRET_ACCESS_KEY\s*=',
    r'PRIVATE KEY',
]

PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all instructions",
    "disregard your",
    "forget your instructions",
    "jailbreak",
    "bypass",
    "pretend you",
    "system prompt",
]

def validate_python_file(file_path: str) -> dict:
    path = PROJECT_ROOT / file_path
    if not path.exists():
        return {"status": "error", "level": "second_level_validation",
                "file": file_path, "message": f"{file_path} does not exist"}
    if path.suffix != ".py":
        return {"status": "skipped", "level": "second_level_validation",
                "file": file_path, "message": "Not a Python file"}
    code = path.read_text(encoding="utf-8", errors="ignore")
    issues = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {"status": "failed", "level": "second_level_validation",
                "file": file_path, "message": f"Syntax error line {e.lineno}: {e.msg}"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_str = ast.unparse(node)
            for danger in DANGEROUS_IMPORTS:
                if danger in import_str:
                    issues.append(f"Dangerous import: {import_str}")
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            issues.append(f"Possible hardcoded secret: '{pattern}'")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_lines = (node.end_lineno or 0) - node.lineno
            if func_lines > 80:
                issues.append(f"Function '{node.name}' too long ({func_lines} lines)")
    if "schemas.py" in file_path or "models" in file_path:
        if "BaseModel" not in code:
            issues.append("Missing BaseModel inheritance")
        if "Field" not in code:
            issues.append("Missing Field definitions")
    if issues:
        return {"status": "warning", "level": "second_level_validation",
                "file": file_path, "issues": issues, "message": f"{len(issues)} issue(s) found"}
    return {"status": "passed", "level": "second_level_validation",
            "file": file_path, "message": "All checks passed"}

def validate_shell_command(command: str) -> dict:
    if not command:
        return {"status": "passed", "message": "Empty command"}
    for pattern in DANGEROUS_COMMANDS:
        if pattern.lower() in command.lower():
            return {"status": "blocked", "level": "second_level_validation",
                    "command": command, "message": f"Dangerous pattern: '{pattern}'"}
    return {"status": "passed", "level": "second_level_validation",
            "command": command, "message": "Command is safe"}

def validate_file_read(file_path: str) -> dict:
    if not file_path:
        return {"status": "passed", "message": "No file path"}
    for sensitive in SENSITIVE_FILES:
        if sensitive in file_path:
            return {"status": "blocked", "level": "second_level_validation",
                    "file": file_path, "message": f"Sensitive file blocked: {sensitive}"}
    return {"status": "passed", "level": "second_level_validation",
            "file": file_path, "message": "File read allowed"}

def validate_prompt(prompt: str) -> dict:
    if not prompt:
        return {"status": "passed", "message": "Empty prompt"}
    prompt_lower = prompt.lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern in prompt_lower:
            return {"status": "blocked", "level": "second_level_validation",
                    "message": f"Prompt injection detected: '{pattern}'"}
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            return {"status": "blocked", "level": "second_level_validation",
                    "message": "Sensitive data in prompt"}
    return {"status": "passed", "level": "second_level_validation",
            "message": "Prompt is safe"}

def validate_mcp_call(tool_name: str, arguments: dict) -> dict:
    if tool_name == "emit_event" and not arguments.get("event_type"):
        return {"status": "blocked", "level": "second_level_validation",
                "message": "emit_event requires event_type"}
    return {"status": "passed", "level": "second_level_validation",
            "tool": tool_name, "message": "MCP call valid"}

def validate_main() -> dict:
    return validate_python_file("main.py")

def validate_schemas() -> dict:
    results = []
    for pattern in ["schemas.py", "models.py"]:
        for f in PROJECT_ROOT.rglob(pattern):
            rel = str(f.relative_to(PROJECT_ROOT))
            if "venv" in rel or "__pycache__" in rel:
                continue
            results.append(validate_python_file(rel))
    if not results:
        return {"status": "skipped", "message": "No schema files found"}
    failed = [r for r in results if r.get("status") in ("failed", "blocked")]
    warnings = [r for r in results if r.get("status") == "warning"]
    return {
        "status": "failed" if failed else ("warning" if warnings else "passed"),
        "level": "second_level_validation",
        "files_checked": len(results),
        "results": results
    }
