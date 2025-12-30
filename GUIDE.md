# Hybrid Agent - Implementation Walkthrough

## 🚀 Key Improvements

We have successfully stabilized the hybrid pentesting agent. Key changes include:

### 1. Side-Channel Exfiltration (Stealth & Stability)
Instead of printing thousands of lines of encrypted data to the shell (which freezes it and gets blocked by Defender), we now use a **Side-Channel** approach:
*   **Victim**: PowerShell extracts the `DPAPI Master Key` and `Login Data` database.
*   **Exfiltration**: PowerShell uses `Invoke-RestMethod` to **upload** these files directly to the agent's `/ups` endpoint (via HTTP POST).
*   **Attacker**: The Python agent receives the files, saves them to `loot/`, and **decrypts them locally**.
*   **Benefit**: Bypasses shell output limits and reducing Defender heuristic noise.

### 2. HTTP Server Stability
We encountered "Empty Response" errors because the single-threaded `HTTPServer` was getting blocked by connection spam.
*   **Fix**: Switched to `ThreadingHTTPServer` to handle multiple connections (User + Victim) simultaneously.
*   **Fix**: Corrected a logic bug where the `do_POST` method was nested inside `do_GET`, blocking the main page.
*   **Fix**: Added rate-limiting to the IP Blocking logs to prevent terminal spam.

### 4. Advanced Capabilities
*   **Secure Directory Persistence**: Install payload to a user-specified "Allowed" folder (e.g., `.../Microsoft projects`) to bypass AV scans.
*   **Live Screen Monitor**: Real-time video feed via "MJPEG-over-HTTP" side-channel.

## 📋 Usage Guide

### Phase 1: auto-Attach
1.  Run `python3 hybrid_agent.py`
2.  Send link `http://YOUR_IP:8080` to victim.
3.  Victim runs the 4 commands.
4.  **Wait 10-15s**. Shell connects automatically.

### Phase 2: Post-Exploitation
Once connected:

**🔐 Persistence (Option 1)**
1.  Select **[5] Secure Dir Persistence**.
2.  Installs to `$env:LOCALAPPDATA\Microsoft\Windows\Microsoft projects`.
3.  SURVIVES REBOOTS!

**🔑 Steal Data (Option 2)**
1.  Select **[3] Browser Credentials**: Decrypts passwords locally.
2.  Select **[5] Live Monitor**:
    *   Starts a background job on victim.
    *   Open `http://IP:8080/watch` to view the stream.
    *   **Cleanup**: Run `Get-Job | Remove-Job -Force` in Raw Shell to stop it.

## ✅ Status: Skeletal Phase Complete
The core infrastructure is fully operational.
*   **Shell**: Stable.
*   **Persistence**: "Safe Zone" method implemented.
*   **Surveillance**: Live Video Feed active.
*   **Exfiltration**: Side-channel upload working.

**Next Steps (Refinement Phase):**
*   Polymorphic Obfuscation (to evade future text-based signatures).
*   SSL/TLS Encryption (HTTPS).
*   Process Injection (Migrate out of PowerShell).
