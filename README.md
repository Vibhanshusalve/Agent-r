#  Agent-R: AI-Powered Pentesting Agent

A hybrid pentesting agent with TLS-encrypted C2, AI-powered autonomous attack mode, and interactive AI assistant.

## Features

- ** TLS Encrypted C2** - All shell communications encrypted with SSL/TLS
- ** AI Autonomous Mode** - DeepSeek Coder 7B decides attack chain automatically
- ** AI Assistant** - Tell the AI what you want in plain English
- ** Persistence** - Multiple methods (Startup, Registry, Secure folder)
- ** Credential Theft** - WiFi passwords, browser credentials, Windows Vault
- ** Live Monitor** - Real-time screen capture stream
- ** Evasion** - Variable obfuscation, LOLBin execution

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Install Ollama (for AI features)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull deepseek-coder:6.7b

# Run the agent
python3 hybrid_agent.py
```

## How It Works

### Phase 1: Get Shell
1. Agent starts HTTP server + TLS listener
2. Send link to target: `http://YOUR_IP:8080/`
3. Target runs the command shown
4. Shell connects with TLS encryption

### Phase 2: Post-Exploitation
```
[1]  Install Persistence
[2]  Steal Data  
[3]   Privilege Escalation
[4]  Raw Shell
[5]  Wait for Reconnect
[6]  AI Autonomous Mode    ← AI attacks automatically
[7]  AI Assistant          ← Tell AI what to do
```

## AI Features

### Autonomous Mode
AI automatically performs:
- Reconnaissance (whoami, hostname, privileges)
- Persistence installation
- Credential extraction

### Assistant Mode
Type natural language commands:
```
> find all wifi passwords
 AI generates: netsh wlan show profiles | ...
> check if I'm admin
 AI generates: whoami /priv
```

## Requirements

- Python 3.8+
- OpenSSL (for TLS cert generation)
- Ollama (for AI features)
- AWS/VPS: Ports 8080, 4444 open

## Files

- `hybrid_agent.py` - Main agent
- `requirements.txt` - Python dependencies
- `loot/` - Exfiltrated data saved here

## Legal

**For authorized security testing only.**

This tool is intended for:
- Penetration testing with written authorization
- Security research and education
- CTF competitions

Unauthorized use is illegal. You are responsible for compliance with applicable laws.

## Credits
Vibhanshu Salve

