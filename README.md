<h1>
❗Redline❗Threat Hunter: Behavioral Log Analysis Engine🛡️</h1>
<br><br>
Redline is an open-source log analysis engine designed to identify suspicious behaviors, potential malware activity, and anomalous execution chains from system/process logs. It uses behavioral heuristics, LOLBin detection, and execution correlation to provide clear recommendations and English-language narratives of security events.
<br><br>
<h2>⤹ <u>Features ⤸ </h2></u>

<h4>
🔺Suspicious Behavior Detection <br></h4>
Detects high-risk paths, commands, processes, and network activity.
<br>
<h4>
🔺LOLBIN & Parent-Child Analysis</h4>
Identifies living-off-the-land binaries and anomalous process chains.
<br>
<h4>
🔺Signal Stacking / Correlation</h4>
Combines multiple indicators across lines to score threats.
<br>
<h4>
🔺English Narratives</h4>
Automatically generates explanations for why an activity is suspicious.
<br>
<h4>
🔺Execution Timeline Visualization</h4>
Chronologically tracks suspicious events for each user/process.
<br>
<h4>
🔺Recommendations</h3>
Suggests BLOCK, MONITOR, or ALLOW based on behavioral scoring.
<br>
<h4>
🔺Ready Python Code</h4>
Clean, modular, and easily extensible for custom threat indicators.

<br><br>
<h2>
⚙️ Installation</h2>

Clone the repository:

git clone https://github.com/Glitchingreality/REDLINE.git
cd redline


Install dependencies:

pip install -r requirements.txt


<h2>
📝 Usage
</h2>
Run the analyzer against a CSV log file:

python redline.py sample_logs.csv


CSV Format Example:
```
timestamp,user,process,parent,path,action,policy
2026-01-22 08:53:01,frank,certutil.exe,cmd.exe,C:\Windows\Temp,FileWrite,Blocked
2026-01-22 08:53:05,frank,certutil.exe,cmd.exe,C:\Windows\Temp,FileWrite,Blocked
2026-01-22 08:53:08,frank,cmd.exe,explorer.exe,C:\Windows\Temp,ProcessStart,Allowed
```

Output includes:

- Per-line score, recommendation, and reasoning

- Execution timeline with suspicious activity highlights

- Narrative summary of key behaviors and escalation points

🖥️ Sample Output<br>
```
=== Execution Timeline for frank ===
[08:53:01] cmd.exe → certutil.exe (ProcessStart)
    • Suspicious command: cmd.exe
    • Suspicious command: certutil
    • LOLBIN execution chain detected: cmd.exe → certutil
    ▲ Elevated activity

Narrative Summary:
  User 'frank' exhibited suspicious behavior beginning at 08:53:01, starting with 'certutil.exe'. The activity progressed through multiple events and culminated in 'cmd.exe'. Key observed behaviors include LOLBIN chains, suspicious commands, and correlated indicators.

⚠ Escalation detected at certutil.exe (08:53:01)
```
