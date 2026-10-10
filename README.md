# SSH-BRUTEFORCE-DETECTION-WAZUH
## Case Study 2 — SSH Password-Guessing Attack Simulation (Hydra)

### Simulate → Attack → Detect → Correlate

I performed a controlled brute-force simulation against the Linux endpoint to reproduce a password-guessing attack and validate that Wazuh detects and alerts on the activity.

The simulation was performed in my own isolated lab environment.

### Simulated Activity

```
sudo apt install -y hydra
hostname -I
sudo systemctl status ssh
nano Password.txt
hydra -l badguy -P ~/Password.txt -t 1 ssh://192.168.89.130
```

![image alt](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/e6eb0b6ed41df5fafc313be2038319047fe4f16e/hydra%20installation.png)



Confirmed the attacker VM could reach the target and that the Hydra tool installed cleanly.

---

## 🔍 Step 1 — Confirm the Target Is Listening

**Target:** `Delucky-Linux` (Agent 002) — `192.168.89.130`

I confirmed the SSH service was active on the target and captured a baseline of `/var/log/auth.log` before the attack, so any new entries could be clearly attributed to the simulation.

[![image alt](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/93b04520d7734415d97dbbf49fe0517262ab3091/ssh%20confirmation%20in%20linux.png)

---

## 🔍 Step 2 — Build the Password List

A small wordlist (`Password.txt`) was created on the attacker VM with three candidate passwords, to keep the simulation controlled and the resulting logs easy to read.

![image alt](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/11361e249cb19a58e9d07d95c1566a3f2e3f901f/password.png)

---

## 🔍 Step 3 — Run the Attack

**Command:**

```
hydra -l badguy -P ~/Password.txt -t 1 ssh://192.168.89.130
```

**Result:** 0 of 1 valid passwords found — expected, since `badguy` is not a real account on the target. I then cross-checked the attempt directly against the target's own log:

```
sudo grep -iE 'Failed password|authentication failure|Invalid user' /var/log/auth.log | tail -n 20
```

The raw `auth.log` entries (`Invalid user badguy`, `Failed password for invalid user badguy`, `PAM 2 more authentication failures`) matched the Hydra run exactly, confirming the attack actually reached the target and was logged locally before I went looking for it in Wazuh.

[![image alt](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/c72309f7c8fd9151b492e6dc6d9f1e61df18d502/brute%20force%20authentication%20failure.png)

---

## 🔍 Step 4 — Detection in Wazuh

**Wazuh Threat Hunting query:**

```
rule.groups:authentication_failed
```

**Rule triggered:** `5710` — *sshd: Attempt to login using a non-existent user* (level 5)

**12 hits**, all generated within the attack window and all tied to the target agent.

[![image alt](screenshots/05-wazuh-discover-12hits.png)](screenshots/05-wazuh-discover-12hits.png)

---

## 🔍 Step 5 — Alert Correlation

I opened a single alert to confirm the fields matched the attack exactly:

- **Agent:** `Delucky-Linux` (`192.168.89.130`)
- **Source user:** `badguy`
- **Rule:** `5710` — non-existent user (`firedtimes: 12`, confirming the 12-alert count)
- **Timestamp:** `2026-10-10T19:36:02.473Z`
- **Raw log:** `Oct 10 19:36:01 ubuntu sshd[4539]: Failed password for invalid user badguy from 192.168.89.130 port 60078 ssh2`

[![image alt](screenshots/06-alert-detail.png)](screenshots/06-alert-detail.png)

I highlighted the key correlation fields — agent name, source IP, and source user — to make the pivot points clear.

[![image alt](screenshots/07-alert-detail-highlighted.png)](screenshots/07-alert-detail-highlighted.png)

Finally, I checked the raw JSON of the alert document to confirm the full event structure Wazuh stored, including `rule.hipaa` and `rule.pci_dss` compliance tags attached automatically to this rule.

[![image alt](screenshots/08-alert-json.png)](screenshots/08-alert-json.png)

---

# 🧩 Event Correlation

| Pivot | Value | Purpose |
|---|---|---|
| Source IP | `192.168.89.130` | Confirms attack traffic originated from the attacker VM |
| Source user | `badguy` | Links all 12 alerts to the same guessed username |
| Rule ID | `5710` | Confirms the alert type — non-existent user, not valid-account brute force |
| Agent | `Delucky-Linux` (002) | Confirms the correct monitored endpoint generated the telemetry |

---

# 🧠 MITRE ATT&CK Mapping

Pulled directly from the Wazuh alert's `rule.mitre` field rather than assumed:

| Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Credential Access | Password Guessing | **T1110.001** | Hydra iterating a password list against a target account |
| Lateral Movement | Remote Services: SSH | **T1021.004** | SSH is the protocol being targeted to gain remote access |

---

# 📋 Compliance Relevance

Rule `5710` is automatically mapped by Wazuh to several compliance frameworks, which is worth highlighting in a SOC portfolio since it shows the detection ties back to real audit requirements, not just MITRE:

| Framework | Control(s) |
|---|---|
| **HIPAA** | 164.312.b |
| **PCI DSS** | 10.2.4, 10.2.5, 10.6.1 |
| **NIST 800-53** | AU.14, AC.7, AU.6 |
| **GDPR** | IV_35.7.d, IV_32.2 |
| **TSC (SOC 2)** | CC6.1, CC6.8, CC7.2, CC7.3 |
| **GPG13** | 7.1 |

These are mostly logging/audit/access-monitoring controls, consistent with this being an authentication-failure detection.

---

# 🚨 Analyst Verdict

### **Verdict: Detected — Low Severity, No Compromise**

The attempt was fully logged and alerted on by Wazuh. No valid credentials were obtained, and the targeted username does not exist on the system, so this activity represents reconnaissance-style password guessing rather than a successful compromise.

Because the username guessed was not a real account, this run exercised Wazuh's **non-existent-user** detection path (rule `5710`) rather than the separate **brute-force correlation rule**, which requires repeated failures against a *valid* account within a short window. Both paths are useful SOC signals, but they represent different attacker behavior and should be documented as distinct detections.

### Recommended SOC Actions

1. Enforce SSH key-based authentication; disable password auth where feasible.
2. Deploy `fail2ban` or a Wazuh active response to automatically block repeat offenders by source IP.
3. Alert on repeated non-existent-user attempts as an early-warning indicator, separate from brute-force correlation.
4. Re-run the simulation against a real local account to validate the brute-force correlation rule as a follow-up case study.

---

# 🧠 Key Lessons Learned

1. **Non-existent-user attempts are a distinct, earlier signal** than brute force against a known account, and worth alerting on separately.
2. **Validating against the raw log matters** — confirming the Wazuh alert against `/var/log/auth.log` proved the detection pipeline wasn't just "trusting the dashboard."
3. **A failed attack is still a successful detection test** — the goal of this simulation was validating visibility, not achieving compromise.
