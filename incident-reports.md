# Incident Reports

Two incident write-ups from a controlled home-lab environment, formatted the way a SOC
analyst would document a real detection-and-response case: timeline, indicators,
detection logic, and remediation.

All activity below took place on an isolated lab network (`192.168.1.0/24`) with the
analyst's own VMs as both attacker and target. No third-party systems were involved.

---

## Incident 001 — Full Port Scan Reconnaissance (Nmap)

**Classification:** Attempted Reconnaissance (MITRE ATT&CK T1046 — Network Service
Scanning)
**Severity:** Low (reconnaissance only, no exploitation attempted)
**Status:** Detected and blocked (IPS)

### Summary

A full 65,535-port SYN scan was launched from `192.168.1.58` (Kali) against a lab host.
The scan was initially **not detected** by Suricata's default ruleset. Investigation
identified two independent configuration issues; after remediation, a custom detection
rule was authored, tested, and subsequently escalated to an active block (IPS).

### Timeline

| Time / Stage | Event |
|---|---|
| T+0 | `nmap -sS -sV -p- <target>` launched from Kali |
| T+~5 min | Scan completes; 3 open TCP ports identified (5040, 5357, 7680) |
| — | Splunk query shows **zero** scan-related alerts despite full port sweep |
| — | `suricata-update` run to refresh ET Open ruleset — still no detection |
| — | Root cause 1 identified: custom rules placed in `/etc/suricata/rules/`, but
`default-rule-path` in `suricata.yaml` pointed to `/var/lib/suricata/rules/` |
| — | Root cause 2 identified: `HOME_NET` set to stale `192.168.181.130/24` instead of
the lab's actual `192.168.1.0/24` |
| — | Both issues corrected; Suricata restarted |
| T+repeat | Scan re-run; custom rule `sid:1000002` fires **11 times** across the scan
duration, consistent with the 60-second threshold window |

### Indicators of Compromise (lab-internal)

| Field | Value |
|---|---|
| Source IP | 192.168.1.58 |
| Destination IP | 192.168.1.39 / 192.168.1.52 (target rotated during testing) |
| Signature | `CUSTOM Nmap SYN Scan` |
| Category | Attempted Information Leak / Attempted Reconnaissance |
| Detection logic | 20+ SYN-only packets from one source within 60 seconds |

### Detection Rule

```
alert tcp any any -> $HOME_NET any (msg:"CUSTOM Nmap SYN Scan"; flags:S;
flow:stateless; threshold:type both, track by_src, count 20, seconds 60;
classtype:attempted-recon; sid:1000002; rev:1;)
```

### Escalation to Prevention (IPS)

Suricata was switched to inline `NFQUEUE` mode (`iptables -I INPUT/OUTPUT -j NFQUEUE`),
and the rule action changed from `alert` to `drop`.

A repeat scan against the now-inline host went from completing in ~5 minutes to sitting
at **0.62% progress after 12 minutes 45 seconds** before being manually terminated —
consistent with silent packet drops rather than a functioning scan.

**Session totals (Suricata `nfq` counters):**

- Packets treated: 124,548
- Accepted: 122,300
- **Dropped: 2,248**
- Alerts: 325

### Root Cause Analysis

Two separate, silent misconfigurations combined to produce a false sense of coverage:

1. Suricata reported "rules successfully loaded" at every restart — the missing custom
   rule produced no error, because the *default* ruleset was still loading correctly
   from the right path. Only the custom addition was affected.
2. The `HOME_NET` variable had not been updated after the lab's network mode changed
   from an earlier NAT/host-only configuration to Bridged. Any rule using `$HOME_NET` as
   a match target was structurally incapable of matching real traffic, with no warning
   at load time.

### Remediation

- Moved `local.rules` to the path specified by `default-rule-path`.
- Corrected `HOME_NET` to `192.168.1.0/24` to reflect actual network topology.
- Added a recurring check (`cat suricata.yaml | grep HOME_NET`) to the lab's setup
  checklist for future network changes.

---

## Incident 002 — SSH Credential Brute-Force (Hydra)

**Classification:** Attempted Credential Access (MITRE ATT&CK T1110 — Brute Force)
**Severity:** Medium (targets an authentication service directly)
**Status:** Detected (default ruleset) and blocked (custom IPS rule)

### Summary

A password brute-force attack was run against SSH (port 22) on a lab host using Hydra,
first with a 10-password list, then with a 2,000-password list derived from
`rockyou.txt`. Unlike the port-scan case, this technique was detected immediately by
the **default** Emerging Threats ruleset with no configuration changes required.

### Timeline

| Time / Stage | Event |
|---|---|
| T+0 | `hydra -l ubuntu -P <10-password list> ssh://192.168.1.52` |
| T+~5s | Attack completes; 0 valid credentials found (expected — list did not contain
the real password) |
| — | Splunk shows 4 alerts on `dest_port=22`, including `ET SCAN LibSSH Based Frequent
SSH Connections Likely BruteForce Attack` and `ET SCAN Potential SSH Scan` — detected
by the default ruleset without any custom signature |
| — | Custom IPS rule authored (`sid:1000003`) and Suricata switched to inline mode |
| T+repeat (small) | 10-password attack re-run; Splunk confirms one `blocked` /
`allowed` pair on the custom signature at the same millisecond the threshold was
crossed |
| T+repeat (large) | 2,000-password attack launched; Hydra's own connection-error
handling disables all worker threads after **31 of 2,000** attempts:
`[ERROR] all children were disabled due too many connection errors` |

### Indicators of Compromise (lab-internal)

| Field | Value |
|---|---|
| Source IP | 192.168.1.15 / 192.168.1.47 / 192.168.1.77 (Kali IP varied across sessions) |
| Destination IP | 192.168.1.52 |
| Destination Port | 22 (SSH) |
| Default-rule signature | `ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack` |
| Custom signature | `CUSTOM SSH Brute Force - BLOCKED` |
| Detection logic (custom) | 5+ SYN-only packets to port 22 from one source within 60 seconds |

### Detection Rule (custom, IPS)

```
drop tcp any any -> $HOME_NET 22 (msg:"CUSTOM SSH Brute Force - BLOCKED"; flags:S;
flow:stateless; threshold:type both, track by_src, count 5, seconds 60;
classtype:attempted-recon; sid:1000003; rev:1;)
```

The threshold (5 attempts/60s) is intentionally stricter than the scan rule's
(20 attempts/60s), reflecting that legitimate SSH clients essentially never open this
many connections this quickly, whereas some normal recon-adjacent traffic can be noisier.

### Outcome Comparison: Detection vs. Attack-Tool Failure

The large-wordlist test produced a materially different outcome from the Nmap case: the
attacking tool did not just slow down, it **disabled itself**. Hydra's connection-error
threshold was reached and it aborted the run with only 1.55% of the wordlist attempted,
compared to Nmap, which continued running (very slowly) rather than aborting.

**Session totals (Suricata `nfq` counters, large-wordlist run):**

- Packets treated: 128,926
- Accepted: 127,823
- **Dropped: 1,103**
- Alerts: 373

### Analysis

The contrast between the two incidents illustrates why detection engineering can't treat
all attack types identically:

- Port scanning is generic enough in its raw packet behavior that a community ruleset
  may not model it tightly, making custom detection necessary.
- Credential brute-forcing against a specific, well-known service (SSH) is a narrower,
  well-documented behavior that community rulesets already cover closely.
- The same enforcement mechanism (inline drop with a threshold rule) had a
  *quantitatively* similar effect (packets dropped) but a *qualitatively* different
  operational impact — degraded performance in one case, tool failure in the other —
  which matters when communicating expected outcomes to stakeholders.

### Remediation / Recommendations

- Custom IPS rule deployed and verified against both small- and large-scale attack
  volumes.
- Recommend rate-limiting or fail2ban-style lockouts at the host level as a
  defense-in-depth complement to network-layer blocking.
- Recommend disabling password-based SSH authentication in favor of key-based auth in
  any non-lab environment, since detection/blocking is a mitigating control, not a
  substitute for reducing the attack surface itself.
