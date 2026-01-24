import re
import sys
from collections import defaultdict
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Install colorama: pip install colorama")
    sys.exit(1)

# =========================
# CONFIGURATION
# =========================

SUSPICIOUS_PATHS = [
    r"\\appdata\\roaming",
    r"\\appdata\\local\\temp",
    r"\\appdata\\local\\packages",
    r"\\appdata\\local\\microsoft\\windows\\inetcache",
    r"\\appdata\\local\\microsoft\\windows\\temporary internet files",
    r"\\appdata\\local\\microsoft\\windows\\history",
    r"\\appdata\\local\\microsoft\\edge\\user data",
    r"\\appdata\\local\\google\\chrome\\user data",
    r"\\programdata",
    r"\\programdata\\microsoft",
    r"\\programdata\\windows",
    r"\\users\\public",
    r"\\users\\default",
    r"\\users\\all users",
    r"\\users\\.*\\downloads",
    r"\\users\\.*\\desktop",
    r"\\users\\.*\\documents",
    r"\\users\\.*\\music",
    r"\\users\\.*\\videos",
    r"\\windows\\temp",
    r"\\windows\\tasks",
    r"\\windows\\system32\\tasks",
    r"\\windows\\system32\\spool\\drivers\\color",
    r"\\windows\\system32\\config",
    r"\\windows\\system32\\drivers",
    r"\\windows\\system32\\wbem",
    r"\\windows\\syswow64",
    r"\\windows\\servicing",
    r"\\windows\\debug",
    r"\\windows\\fonts",
    r"\\windows\\help",
    r"\\windows\\ime",
    r"\\windows\\inf",
    r"\\windows\\logs",
    r"\\windows\\media",
    r"\\windows\\registration",
    r"\\windows\\system32\\com",
    r"\\windows\\system32\\fxt",
    r"\\windows\\system32\\logfiles",
    r"\\windows\\system32\\migration",
    r"\\windows\\system32\\oobe",
    r"\\windows\\system32\\restore",
    r"\\windows\\system32\\sru",
    r"\\windows\\system32\\sysprep",
    r"\\windows\\system32\\winevt",
    r"\\windows\\system32\\wmi",
    r"\\windows\\tracing",
    r"startup",
    r"start menu\\programs\\startup",
    r"\\microsoft\\windows\\start menu\\programs\\startup",
    r"\\onedrive\\temp",
    r"\\onedrive\\cache",
    r"\\recycle.bin",
    r"\\\$recycle.bin",
    r"\\perfLogs",
    r"\\intel\\logs",
    r"\\nvidia\\corporation",
    r"\\amd",
    r"/tmp/",
    r"/var/tmp/",
    r"/dev/shm",
    r"/etc/cron",
    r"/etc/cron.d",
    r"/etc/cron.daily",
    r"/etc/init.d",
    r"/etc/systemd/system",
    r"/etc/profile.d",
    r"/etc/rc.local",
    r"/usr/local/bin",
    r"/usr/bin",
    r"/usr/sbin",
    r"/opt/",
    r"/library/launchagents",
    r"/library/launchdaemons",
    r"/users/.*/library/application support",
    r"/users/.*/library/launchagents",
    r"/private/var/tmp",
    r"/private/tmp"
]


SUSPICIOUS_COMMANDS = [
    "powershell",
    "pwsh",
    "invoke-expression",
    "iex",
    "frombase64string",
    "-enc",
    "-encodedcommand",
    "downloadstring",
    "invoke-webrequest",
    "start-bitstransfer",
    "new-object net.webclient",
    "add-mppreference",
    "set-mppreference",
    "disable-realtimemonitoring",
    "remove-mppreference",
    "cmd.exe",
    "/c",
    "/k",
    "whoami",
    "ipconfig",
    "net user",
    "net localgroup",
    "net group",
    "net use",
    "net share",
    "sc create",
    "sc start",
    "sc stop",
    "schtasks",
    "at.exe",
    "wmic",
    "wevtutil cl",
    "reg add",
    "reg delete",
    "reg query",
    "reg save",
    "regsvr32",
    "rundll32",
    "mshta",
    "cscript",
    "wscript",
    "certutil",
    "-decode",
    "-urlcache",
    "bitsadmin",
    "curl",
    "wget",
    "ftp",
    "tftp",
    "nc",
    "ncat",
    "telnet",
    "ssh",
    "socat",
    "bash -i",
    "sh -i",
    "zsh -i",
    "python -c",
    "python3 -c",
    "perl -e",
    "php -r",
    "ruby -e",
    "base64 -d",
    "base64 --decode",
    "openssl enc",
    "chmod +x",
    "chown",
    "nohup",
    "disown",
    "kill -9",
    "pkill",
    "ps aux",
    "crontab",
    "systemctl enable",
    "systemctl start",
    "launchctl load",
    "launchctl bootstrap",
    "defaults write",
    "osascript",
    "xattr -d",
    "spctl --master-disable"
]


SUSPICIOUS_PROCESSES = [
    # Core LOLBins / Script Hosts
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "schtasks.exe",
    "at.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "installutil.exe",
    "msbuild.exe",
    "forfiles.exe",
    "scriptrunner.exe",

    # System Abuse Targets
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "winlogon.exe",
    "explorer.exe",
    "taskhostw.exe",
    "taskmgr.exe",
    "conhost.exe",

    # Download / Network Tools
    "curl.exe",
    "wget.exe",
    "ftp.exe",
    "tftp.exe",
    "nc.exe",
    "ncat.exe",
    "telnet.exe",
    "ssh.exe",
    "plink.exe",
    "socat.exe",

    # Interpreters / Living-off-the-Land
    "python.exe",
    "pythonw.exe",
    "python3.exe",
    "perl.exe",
    "php.exe",
    "ruby.exe",
    "java.exe",
    "node.exe",
    "deno.exe",

    # Compression / Payload Handling
    "7z.exe",
    "7za.exe",
    "winrar.exe",
    "rar.exe",
    "tar.exe",
    "gzip.exe",

    # Persistence / Autorun Helpers
    "reg.exe",
    "sc.exe",
    "net.exe",
    "net1.exe",
    "wevtutil.exe",
    "bcdedit.exe",
    "icacls.exe",
    "takeown.exe",

    # Credential / Memory Access
    "procdump.exe",
    "comsvcs.dll",
    "mimikatz.exe",
    "nanodump.exe",

    # macOS / Linux Cross-Platform
    "bash",
    "sh",
    "zsh",
    "dash",
    "cron",
    "crond",
    "launchctl",
    "osascript",
    "systemctl",

    # Red-Team / Dual-Use Frameworks
    "cobaltstrike.exe",
    "beacon.exe",
    "empire.exe",
    "metasploit.exe",
    "msfconsole",
    "meterpreter"
]


NETWORK_INDICATORS = [
    r"https?://",
    r"\b\d{1,3}(\.\d{1,3}){3}\b",
    r"\.onion",
]

ENCODING_INDICATORS = [
    "base64",
    "-enc",
    "-encodedcommand",
]

LOLBIN_COMBOS = [
    # PowerShell execution & obfuscation
    ("powershell", "frombase64string"),
    ("powershell", "invoke-expression"),
    ("powershell", "iex"),
    ("powershell", "-enc"),
    ("powershell", "downloadstring"),
    ("powershell", "invoke-webrequest"),
    ("powershell", "start-bitstransfer"),
    ("powershell", "new-object net.webclient"),

    # PowerShell defense evasion
    ("powershell", "disable-realtimemonitoring"),
    ("powershell", "add-mppreference"),
    ("powershell", "set-mppreference"),

    # CMD-based staging
    ("cmd.exe", "powershell"),
    ("cmd.exe", "certutil"),
    ("cmd.exe", "bitsadmin"),
    ("cmd.exe", "curl"),
    ("cmd.exe", "wget"),
    ("cmd.exe", "ftp"),
    ("cmd.exe", "tftp"),

    # Certutil abuse
    ("certutil", "-decode"),
    ("certutil", "-urlcache"),
    ("certutil", "http"),

    # Script host chains
    ("wscript.exe", "powershell"),
    ("cscript.exe", "powershell"),
    ("mshta.exe", "powershell"),
    ("mshta.exe", "http"),

    # DLL / binary proxy execution
    ("rundll32", "http"),
    ("rundll32", "javascript"),
    ("regsvr32", "http"),
    ("regsvr32", "scrobj.dll"),

    # Task & persistence chains
    ("schtasks", "powershell"),
    ("schtasks", "cmd.exe"),
    ("schtasks", "rundll32"),
    ("at.exe", "cmd.exe"),
    ("sc create", "binpath"),
    ("sc start", "powershell"),

    # Registry-based execution
    ("reg add", "run"),
    ("reg add", "runonce"),
    ("reg add", "image file execution options"),

    # Living-off-the-land download + execute
    ("curl", "| sh"),
    ("wget", "| sh"),
    ("curl", "bash"),
    ("wget", "bash"),

    # Linux/macOS LOLBins
    ("bash", "-i"),
    ("sh", "-i"),
    ("python", "-c"),
    ("python3", "-c"),
    ("perl", "-e"),
    ("php", "-r"),
    ("ruby", "-e"),

    # Encoding / decoding chains
    ("base64", "-d"),
    ("openssl", "enc"),
    ("xxd", "-r"),

    # Network + execution
    ("nc", "-e"),
    ("ncat", "-e"),
    ("socat", "exec"),
    ("telnet", "| sh"),
    ("ssh", "proxycommand"),

    # Credential & discovery chains
    ("wmic", "process call create"),
    ("wmic", "shadowcopy"),
    ("wevtutil", "cl"),
    ("net user", "/add"),
    ("net localgroup", "/add"),

    # macOS persistence
    ("launchctl", "load"),
    ("launchctl", "bootstrap"),
    ("defaults write", "loginwindow"),

    # Advanced dual-use
    ("msbuild", "inline task"),
    ("installutil", "/u"),
    ("forfiles", "cmd.exe")
]

PARENT_CHILD_ANOMALIES = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
]

WEIGHTS = {
    "path": 2,
    "command": 3,
    "process": 2,
    "network": 2,
    "encoding": 4,
}

# =========================
# STATE
# =========================

EXECUTION_CHAINS = defaultdict(list)
TIMELINE = defaultdict(list)

# =========================
# HELPERS
# =========================

def severity_color(score):
    if score >= 8:
        return Fore.RED + Style.BRIGHT
    elif score >= 5:
        return Fore.YELLOW + Style.BRIGHT
    elif score >= 3:
        return Fore.CYAN
    return Fore.GREEN

def parse_timestamp(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def parse_log_line(line):
    parts = [p.strip() for p in line.split(",")]
    return {
        "timestamp": parts[0] if len(parts) > 0 else None,
        "user": parts[1] if len(parts) > 1 else "unknown",
        "process": parts[2] if len(parts) > 2 else "unknown",
        "parent": parts[3] if len(parts) > 3 else "unknown",
        "path": parts[4] if len(parts) > 4 else "",
        "action": parts[5] if len(parts) > 5 else "",
        "policy": parts[6] if len(parts) > 6 else "",
    }

# =========================
# ANALYSIS ENGINE
# =========================

def analyze_line(line, context):
    score = 0
    findings = []
    signals = 0
    intent_multiplier = 1.0

    lower = line.lower()
    chain_key = f"{context['user']}::{context['process']}"
    EXECUTION_CHAINS[chain_key].append(lower)
    recent = " ".join(EXECUTION_CHAINS[chain_key][-5:])

    for path in SUSPICIOUS_PATHS:
        if re.search(path, recent):
            score += WEIGHTS["path"]
            signals += 1
            findings.append(f"Suspicious path usage: {path}")

    for cmd in SUSPICIOUS_COMMANDS:
        if cmd in recent:
            score += WEIGHTS["command"]
            signals += 1
            findings.append(f"Suspicious command: {cmd}")

    for proc in SUSPICIOUS_PROCESSES:
        if proc in recent:
            score += WEIGHTS["process"]
            signals += 1
            findings.append(f"Suspicious process: {proc}")

    for net in NETWORK_INDICATORS:
        if re.search(net, recent):
            score += WEIGHTS["network"]
            signals += 1
            findings.append("Network indicator detected")

    for enc in ENCODING_INDICATORS:
        if enc in recent:
            score += WEIGHTS["encoding"]
            signals += 1
            findings.append("Encoded or obfuscated payload detected")

    for a, b in LOLBIN_COMBOS:
        if a in recent and b in recent:
            score += 4
            signals += 1
            intent_multiplier += 0.5
            findings.append(f"LOLBIN execution chain detected: {a} → {b}")

    for parent, child in PARENT_CHILD_ANOMALIES:
        if parent in recent and child in recent:
            score += 5
            signals += 1
            intent_multiplier += 0.5
            findings.append(f"Suspicious parent-child execution: {parent} → {child}")

    if signals >= 3:
        score = int(score * intent_multiplier)
        findings.append("Multiple correlated indicators detected (signal stacking)")

    return score, findings

# =========================
# DECISION ENGINE
# =========================

def threatlocker_recommendation(score, findings):
    text = " ".join(findings).lower()
    if score >= 8:
        return Fore.RED + Style.BRIGHT + "BLOCK"
    if score >= 5 or "lolbin" in text or "encoded" in text:
        return Fore.YELLOW + Style.BRIGHT + "MONITOR"
    return Fore.GREEN + Style.BRIGHT + "ALLOW"

def explain_decision(score, findings, context):
    if score >= 8:
        return "Multiple high-risk behaviors indicate probable malicious execution"
    if "encoded" in " ".join(findings).lower():
        return "Obfuscation suggests intent to evade detection"
    if context["policy"].lower() == "blocked" and score == 0:
        return "Policy blocked benign access to protected resource"
    return "No malicious behavioral indicators detected"
# =========================
# NARRATIVE ENGINE
# =========================

def generate_narrative(user, events):
    high = [e for e in events if e["score"] >= 5]
    if not high:
        return "No suspicious activity detected for this user."

    first = high[0]
    last = high[-1]

    behaviors = set()
    for e in high:
        for f in e["findings"]:
            behaviors.add(f)

    return (
        f"User '{user}' exhibited suspicious behavior beginning at "
        f"{first['time'].strftime('%H:%M:%S') if first['time'] else 'an unknown time'}, "
        f"starting with '{first['process']}'. "
        f"The activity progressed through {len(high)} notable events and culminated "
        f"in '{last['process']}'. "
        f"Key observed behaviors include: "
        + "; ".join(list(behaviors)[:5])
        + "."
    )

# =========================
# TIMELINE
# =========================

def escalation_point(events):
    for e in events:
        if e["score"] >= 5:
            return e
    return None

def print_timeline(user):
    events = sorted(TIMELINE[user], key=lambda e: e["time"] or datetime.min)

    print(Fore.MAGENTA + Style.BRIGHT + f"\n=== Execution Timeline for {user} ===")

    for e in events:
        t = e["time"].strftime("%H:%M:%S") if e["time"] else "UNKNOWN"
        color = severity_color(e["score"])

        print(color + f"[{t}] {e['parent']} → {e['process']} ({e['action']})")

        for f in e["findings"]:
            print(color + f"    • {f}")

        if e["score"] >= 5:
            print(color + "    ▲ Elevated activity")

    # Narrative summary (new)
    narrative = generate_narrative(user, events)
    print(Fore.CYAN + Style.BRIGHT + "\nNarrative Summary:")
    print(Fore.CYAN + f"  {narrative}")

    pivot = escalation_point(events)
    if pivot:
        print(
            Fore.RED + Style.BRIGHT +
            f"\n⚠ Escalation detected at {pivot['process']} "
            f"({pivot['time'].strftime('%H:%M:%S') if pivot['time'] else 'UNKNOWN'})"
        )
# =========================
# MAIN DRIVER
# =========================

def process_log(file_path):
    with open(file_path, "r", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue    
# 🔍 STEP 1: Skip INFO / WARN meta lines
    if line.startswith("[INFO]") or line.startswith("[WARN]"):
        continue
        #CONTINUE
            context = parse_log_line(line)
            score, findings = analyze_line(line, context)
            recommendation = threatlocker_recommendation(score, findings)
            explanation = explain_decision(score, findings, context)
            color = severity_color(score)

            TIMELINE[context["user"]].append({
                "time": parse_timestamp(context["timestamp"]),
                "process": context["process"],
                "parent": context["parent"],
                "action": context["action"],
                "path": context["path"],
                "score": score,
                "findings": findings,
                "policy": context["policy"],
            })

            print(color + f"[Line {lineno}] Score={score} | Recommendation: {recommendation}")
            print(color + f"  {line}")
            print(color + f"    Reason: {explanation}")
            for f in findings:
                print(color + f"    → {f}")
            print()

    for user in TIMELINE:
        if any(e["score"] >= 5 for e in TIMELINE[user]):
            print_timeline(user)

# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python threat_hunter.py <logfile>")
        sys.exit(1)

    print(Fore.BLUE + Style.BRIGHT + "\n=== Threat Hunter Engine Initialized ===\n")
    process_log(sys.argv[1])

