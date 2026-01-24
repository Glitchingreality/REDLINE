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
    r"\\users\\.*\\downloads",
    r"/tmp/",
    r"/var/tmp/",
    r"/etc/cron",
    r"/usr/bin",
    r"/opt/",
    r"/private/tmp",
]

SUSPICIOUS_COMMANDS = [
    "powershell", "cmd.exe", "certutil", "curl", "wget", "mshta", "-enc", "encodedcommand"
]

SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "certutil.exe"
]

NETWORK_INDICATORS = [
    r"https?://",
    r"\b\d{1,3}(\.\d{1,3}){3}\b",
]

ENCODING_INDICATORS = [
    "-enc",
    "base64",
]

LOLBIN_COMBOS = [
    ("powershell", "-enc"),
    ("cmd.exe", "certutil"),
    ("mshta", "powershell"),
]

PARENT_CHILD_ANOMALIES = [
    ("winword.exe", "powershell.exe"),
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
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except Exception:
            continue
    return None

def parse_log_line(line):
    line = line.strip()

    # -------------------------
    # INFO LINES
    # -------------------------
    if line.startswith("[INFO]"):
        fields = dict(
            item.split("=", 1)
            for item in line.replace("[INFO]", "").strip().split()
            if "=" in item
        )
        return {
            "timestamp": fields.get("time"),
            "user": fields.get("user", "system"),
            "process": fields.get("proc", "info"),
            "parent": fields.get("parent", "system"),
            "path": "",
            "action": fields.get("verdict", "Info"),
            "policy": fields.get("reason", ""),
            "event_type": "info",
        }

    # -------------------------
    # WARN LINES
    # -------------------------
    if line.startswith("[WARN]"):
        tokens = line.replace("[WARN]", "").strip().split()
        timestamp = " ".join(tokens[0:2]) if len(tokens) >= 2 else None
        user = "unknown"
        for t in tokens:
            if t.startswith("user="):
                user = t.split("=", 1)[1]
        return {
            "timestamp": timestamp,
            "user": user,
            "process": "warning",
            "parent": "system",
            "path": "",
            "action": "Warning",
            "policy": " ".join(tokens[2:]),
            "event_type": "warn",
        }

    # -------------------------
    # DEFAULT CSV / EXECUTION LOGS
    # -------------------------
    parts = [p.strip() for p in line.split(",")]
    return {
        "timestamp": parts[0] if len(parts) > 0 else None,
        "user": parts[1] if len(parts) > 1 else "unknown",
        "process": parts[2] if len(parts) > 2 else "unknown",
        "parent": parts[3] if len(parts) > 3 else "unknown",
        "path": parts[4] if len(parts) > 4 else "",
        "action": parts[5] if len(parts) > 5 else "",
        "policy": parts[6] if len(parts) > 6 else "",
        "event_type": "execution",
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

    # Narrative summary
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

            # -------------------------
            # Parse the line first
            # -------------------------
            context = parse_log_line(line)

            # -------------------------
            # Analyze the line
            # -------------------------
            score, findings = analyze_line(line, context)
            recommendation = threatlocker_recommendation(score, findings)
            explanation = explain_decision(score, findings, context)
            color = severity_color(score)

            # -------------------------
            # Append directly to TIMELINE using parsed context
            # -------------------------
            TIMELINE[context["user"]].append({
                "time": parse_timestamp(context.get("timestamp")),
                "process": context.get("process"),
                "parent": context.get("parent"),
                "action": context.get("action"),
                "path": context.get("path"),
                "score": score,
                "findings": findings,
                "policy": context.get("policy"),
                "event_type": context.get("event_type"),
            })

            # -------------------------
            # CLI output
            # -------------------------
            print(color + f"[Line {lineno}] Score={score} | Recommendation: {recommendation}")
            print(color + f"  {line}")
            print(color + f"    Reason: {explanation}")
            for f in findings:
                print(color + f"    → {f}")
            print()

    # -------------------------
    # Print timeline per user
    # -------------------------
    for user in TIMELINE:
        if any(e["score"] >= 5 for e in TIMELINE[user]):
            print_timeline(user)


# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python redline.py <logfile>")
        sys.exit(1)

    print(Fore.BLUE + Style.BRIGHT + "\n=== Threat Hunter Engine Initialized ===\n")
    process_log(sys.argv[1])

