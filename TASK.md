# Hybrid Pentesting Agent

## Goal
Combine auto-exploitation with interactive post-exploitation menu.

## Flow
1. **Phase 1 - Auto Attack**
   - Serve ClickFix link
   - Victim clicks → shell connects automatically
   
2. **Phase 2 - Interactive Post-Exploitation**
   - Once shell connected, show menu:
     ```
     Shell Connected! What do you want to do?
     ├── 1. Persistence
     │   ├── Startup Folder
     │   ├── Registry Run
     │   └── Scheduled Task
     ├── 2. Steal Data
     │   ├── WiFi Passwords
     │   ├── Browser Credentials
     │   └── Windows Vault
     ├── 3. Privilege Escalation
     │   ├── UAC Bypass
     │   └── Check Privs
     ├── 4. Raw Shell (manual)
     └── 0. Exit
     ```
   - User selects → Agent sends commands through shell

## Tasks
- [x] Create hybrid_agent.py with socket-based shell manager
- [x] Implement HTTP server for ClickFix link
- [x] Implement shell connection handler
- [x] Implement post-exploitation menu
- [x] Implement command execution through shell
- [x] Test full flow
- [x] Implement Secure Directory Persistence (Defender Exclusion)
- [x] Implement Live Screen Monitor (MJPEG Stream)
