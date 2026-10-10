# SSH Password-Guessing Simulation & Wazuh Authentication-Failure Monitoring

**Portfolio case study | Blue Team / SOC L1 | Ubuntu | OpenSSH | Hydra | Wazuh**

> **Result:** A controlled lab simulation produced SSH authentication-failure telemetry. Wazuh recorded a level-5 alert, rule **5710**, for an attempt using the non-existent username `badguy`. The event was reviewed using the alert fields and raw SSH log. No successful login or compromise was demonstrated.

## Project overview

| Component | Details |
|---|---|
| SIEM | Wazuh |
| Monitored endpoint | `Delucky-Linux`, agent ID `002` |
| Endpoint IP in alert | `192.168.89.130` |
| Wazuh manager/dashboard | `192.168.89.128` (lab address) |
| Service | OpenSSH (`sshd`) |
| Test username | `badguy` (non-existent user) |
| Alert | Rule `5710`, level `5` |
| Outcome | Failed authentication detected; no compromise shown |

## 1. Objective

I tested whether SSH authentication failures from a small, controlled password-guessing simulation would be recorded by the Linux endpoint and surfaced in Wazuh. The work was performed in my own lab, not against a third-party system.

## 2. Lab preparation

I checked the SSH service, prepared a small wordlist containing three dummy candidate passwords, and confirmed the endpoint was available for the test.

![Hydra installation](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/e6eb0b6ed41df5fafc313be2038319047fe4f16e/hydra%20installation.png)

![SSH service confirmation](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/93b04520d7734415d97dbbf49fe0517262ab3091/ssh%20confirmation%20in%20linux.png)

![Dummy password list](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/11361e249cb19a58e9d07d95c1566a3f2e3f901f/password.png)

## 3. Simulation and endpoint validation

The test used the username `badguy`, which does not exist on the endpoint. Hydra reported **0 of 1 valid passwords found**, as expected for that username. I then checked the endpoint's SSH authentication logs for invalid-user and failed-password entries.

![SSH authentication-failure log](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/c72309f7c8fd9151b492e6dc6d9f1e61df18d502/brute%20force%20authentication%20failure.png)

## 4. Wazuh detection

I searched Wazuh Discover using:

```text
rule.groups:authentication_failed
```

The alert details showed:

- **Rule ID:** `5710`
- **Description:** `sshd: Attempt to login using a non-existent user`
- **Level:** `5`
- **Username:** `badguy`
- **Program:** `sshd`
- **Agent:** `Delucky-Linux` (ID `002`)
- **Raw event time:** `Oct 10 19:36:01`
- **Wazuh event time:** `2026-10-10T19:36:02.473Z`
- **Raw log:** `Failed password for invalid user badguy from 192.168.89.130 port 60078 ssh2`

The Discover view showed 12 matching results, and the selected alert included `firedtimes: 12`. I record these as the count shown in the interface and rule metadata, not proof of 12 unique attempts without further correlation.

![Wazuh Discover results](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/dcff5c7381df945f37d1c2e8e05c9df95749b35f/brute%20force%20sshd%20login%20details.png)

![Wazuh alert details](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/65f1ea2c7dcc20a1f798ae20c43c1b3df9bd167b/vvvv.png)

![Alert fields highlighted](https://github.com/DeluckyOG/SSH-BRUTEFORCE-DETECTION-WAZUH/blob/445ae0099bdd8a851971c6b2be59f5c8e529ea4c/Document%20brute%20Force%20login.png)

## 5. Raw alert JSON evidence

This is a readable text transcription of the key fields from the Wazuh alert provided for this case study.

```json
{
  "_index": "wazuh-alerts-4.x-2026.10.10",
  "_id": "l8ZQJ6EBgMXsDZcPuKO3",
  "_source": {
    "predecoder": {
      "hostname": "ubuntu",
      "program_name": "sshd",
      "timestamp": "Oct 10 19:36:01"
    },
    "agent": {"ip": "192.168.89.130", "name": "Delucky-Linux", "id": "002"},
    "manager": {"name": "wazuh"},
    "data": {"srcuser": "badguy", "srcip": "192.168.89.130"},
    "rule": {
      "level": 5,
      "description": "sshd: Attempt to login using a non-existent user",
      "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"],
      "firedtimes": 12,
      "mitre": {
        "technique": ["Password Guessing", "SSH"],
        "id": ["T1110.001", "T1021.004"],
        "tactic": ["Credential Access", "Lateral Movement"]
      },
      "id": "5710",
      "hipaa": ["164.312.b"],
      "pci_dss": ["10.2.4", "10.2.5", "10.6.1"],
      "tsc": ["CC6.1", "CC6.8", "CC7.2", "CC7.3"],
      "nist_800_53": ["AU.14", "AC.7", "AU.6"],
      "gdpr": ["IV_35.7.d", "IV_32.2"],
      "gpg13": ["7.1"]
    },
    "decoder": {"parent": "sshd", "name": "sshd"},
    "full_log": "Oct 10 19:36:01 ubuntu sshd[4539]: Failed password for invalid user badguy from 192.168.89.130 port 60078 ssh2",
    "input": {"type": "log"},
    "@timestamp": "2026-10-10T19:36:02.473Z",
    "location": "journald",
    "timestamp": "2026-10-10T19:36:02.473+0000"
  },
  "fields": {
    "timestamp": ["2026-10-10T19:36:02.473Z"],
    "@timestamp": ["2026-10-10T19:36:02.473Z"]
  }
}
```

## 6. Analyst interpretation and limitations

### Source-IP discrepancy

The JSON reports `192.168.89.130` for both the monitored agent IP and the SSH event's source IP. This alert alone does **not** prove the connection originated from a separate attacker VM. The next step is to verify the testing VM's actual IP and network mode, then compare it with the endpoint's SSH logs before attributing the source.

### What the evidence does and does not establish

- It records an SSH failed-authentication event for a non-existent username.
- Rule 5710 is an **invalid-user detection**; it is not, by itself, proof that a separate repeated-failure/brute-force correlation rule fired.
- The provided evidence does not show successful authentication, account compromise, or lateral movement.
- MITRE labels are rule metadata, not proof that every mapped tactic occurred.

## 7. MITRE ATT&CK metadata

| ID | Wazuh label | Interpretation |
|---|---|---|
| `T1110.001` | Password Guessing | Relevant to the password-list simulation |
| `T1021.004` | SSH | SSH was the service involved; successful access was not shown |

## 8. Compliance metadata in the alert

| Framework | Values in the rule metadata |
|---|---|
| HIPAA | `164.312.b` |
| PCI DSS | `10.2.4`, `10.2.5`, `10.6.1` |
| NIST 800-53 | `AU.14`, `AC.7`, `AU.6` |
| GDPR | `IV_35.7.d`, `IV_32.2` |
| TSC / SOC 2 | `CC6.1`, `CC6.8`, `CC7.2`, `CC7.3` |
| GPG13 | `7.1` |

These are tags attached to the Wazuh rule. They do not certify that the lab or an organization complies with those frameworks.

## 9. SOC analyst verdict

**Verdict: Authentication-failure activity detected; no compromise demonstrated.**

The endpoint log and Wazuh alert support the conclusion that an SSH attempt was made with the non-existent username `badguy`. Source-IP attribution remains unresolved and should be verified before identifying a separate attacker host.

### Recommended next steps

1. Verify the test VM IP and network mode, then correlate the source with endpoint logs.
2. Review surrounding SSH events to establish the number and pattern of distinct failures.
3. In the isolated lab, run a separate controlled test against a known local test account if permitted, and document whether a repeated-failure correlation rule actually triggers.
4. Consider SSH key-based authentication, limiting SSH exposure, and rate-limiting protections such as Fail2ban.
5. Keep the raw log, alert JSON, search query, timestamps, and screenshots together as reproducible evidence.

## 10. Key learning outcomes

- Generated controlled SSH authentication-failure telemetry.
- Investigated an alert by pivoting from Wazuh Discover to its rule details and raw log.
- Cross-checked SIEM evidence against endpoint logs.
- Distinguished an invalid-user alert from proof of compromise or a separate brute-force correlation.
- Identified a source-IP attribution gap instead of assuming the origin.

---

*Personal lab case study for cybersecurity learning and SOC portfolio development.*
