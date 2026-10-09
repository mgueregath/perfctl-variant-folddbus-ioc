# perfctl variant (folddbus-send / tpm_dev_wq / libgcwrap): case analysis, eradication guide and IOCs

**Language:** English · [Español](README.es.md)

A field-tested write-up of a real compromise of a Linux/Docker server by a **perfctl-family Monero miner with a rootkit**, and of how it was removed **without reinstalling**. It documents a newer variant than the ones in public reports, with behaviors not described elsewhere:

- a **resident Go implant hidden inside the `crond.service` cgroup**, masquerading as `s6-supervise`, that rewrites root's crontab every 10 seconds and recreates anything you delete;
- **credential and terminal-session capture** (a PAM hook plus bash session recordings) and a **hidden Tor service**;
- `trufflehog` run as root to hunt for secrets, plus **proxyjacking** (Traffmonetizer);
- **system accounts (`ftp`, `lp`) turned into SSH backdoors**, with a copy of bash as their shell (`"/sbin/nologin "`, trailing space).

> **The value of this repository is in the detailed documents below**, especially the [eradication guide](docs/en/ERADICATION-GUIDE.md): exact commands, the order that works, how to see through the rootkit, how to verify, and the mistakes that made intermediate cleanups fail.

All victim-identifying information has been removed. Malware samples are **not** included.

---

## Start here

| If you are... | Go to |
|---|---|
| **Responding to a suspected infection right now** | [Eradication guide](docs/en/ERADICATION-GUIDE.md), starting with [Golden rules](docs/en/ERADICATION-GUIDE.md#1-golden-rules) and [Trusted view](docs/en/ERADICATION-GUIDE.md#3-trusted-view-seeing-the-server-without-the-rootkit) |
| **Checking whether a host is affected** | Run [`verify-perfctl.sh`](verify-perfctl.sh) (read-only), then read [Confirm the infection](docs/en/ERADICATION-GUIDE.md#5-confirm-the-infection) |
| **Building detections / hunting** | [`iocs/perfctl-folddbus-iocs.csv`](iocs/perfctl-folddbus-iocs.csv) and the [Quick detection tips](#quick-detection-tips) below |
| **Trying to understand what happened** | [Case report](docs/en/REPORT.md) |
| **Deciding between cleaning and reinstalling** | [When to reinstall (don't clean)](docs/en/ERADICATION-GUIDE.md#14-when-to-reinstall-dont-clean) |
| **Worried about leaked credentials** | [After cleaning up](docs/en/ERADICATION-GUIDE.md#12-after-cleaning-up) |

---

## What is in this repository

| Document | What you get |
|---|---|
| **[docs/en/ERADICATION-GUIDE.md](docs/en/ERADICATION-GUIDE.md)** · [ES](docs/es/GUIA-ERRADICACION.md) | **The main piece.** 15 sections and 2 appendices: how the malware works and why the order matters ([§0](docs/en/ERADICATION-GUIDE.md#0-what-this-malware-does-to-understand-the-order)); golden rules; a **musl-container "trusted view"** that sees what the rootkit hides ([§3](docs/en/ERADICATION-GUIDE.md#3-trusted-view-seeing-the-server-without-the-rootkit)); evidence preservation; access containment; **how to find and kill the hidden implant through cgroups** ([§7](docs/en/ERADICATION-GUIDE.md#7-neutralize-the-resident-implant)); removing the rootkit and its `chattr +i` files ([§8](docs/en/ERADICATION-GUIDE.md#8-remove-the-rootkit)); restoring profiles, accounts, keys and kernel settings; a verification checklist with expected results ([§11](docs/en/ERADICATION-GUIDE.md#11-verification)); credential rotation and monitoring with `auditd` ([§12](docs/en/ERADICATION-GUIDE.md#12-after-cleaning-up)); explicit criteria for reinstalling ([§14](docs/en/ERADICATION-GUIDE.md#14-when-to-reinstall-dont-clean)); and **10 mistakes that broke intermediate attempts** ([§15](docs/en/ERADICATION-GUIDE.md#15-mistakes-that-broke-intermediate-attempts)). Debian/Ubuntu equivalents included. |
| **[docs/en/REPORT.md](docs/en/REPORT.md)** · [ES](docs/es/INFORME.md) | The case analysis: symptoms, a table of matches with the documented perfctl, the 13 new behaviors in this variant, what worked for detection, the cleanup order, and what remains unknown. |
| **[verify-perfctl.sh](verify-perfctl.sh)** | A **read-only** Bash script that checks ~30 indicators (rootkit loaded via `ldd`, known paths, cron and profile persistence, backdoor accounts and keys, hugepages, `core_pattern`, suspicious executables, processes **hidden from `/proc` but present in cgroups**, immutable files, package integrity, proxyjacking). Exit code 1 if anything is found. |
| **[iocs/perfctl-folddbus-iocs.csv](iocs/perfctl-folddbus-iocs.csv)** | Indicators of compromise with English and Spanish descriptions: SHA-256 hashes, paths, process names, environment variables, persistence lines, the attacker's SSH key fingerprint and symptoms. |

---

## Key findings at a glance

- **Compromise window:** about 63 hours; found and cleaned the same day. Initial access vector **not determined** (Polkit CVE-2021-4034 was patched; no RocketMQ).
- **Why `top`/`ps`/`ls` lied:** `/lib/libgcwrap.so` loaded through `/etc/ld.so.preload` hooks glibc; fake `top`/`ldd`/`crontab` hid the rest. The hook also hid itself.
- **Why deleting files did not work:** the implant lived in the `crond.service` cgroup and re-created everything within seconds. **Stop that cgroup first.**
- **What gave it away:** `ldd /usr/bin/ls` listing the rootkit; hugepages reserved at runtime; PIDs present in `cgroup.procs` but absent from `/proc`; an `auditd` `execve` rule on `crontab`.
- **Damage assessment:** the malware captured PAM authentication data and bash sessions for the whole period. **Treat every credential used on the host as exposed.**
- **Verification trap:** a first cleanup looked complete, but the implant recreated `/etc/profile`, `.bash_profile`, `/etc/cron.d/perfclean`, fake binaries and a second backdoor account **before it was killed**. Only a full verification run found them hours later.

Timeline, new behaviors and the full cleanup order are in the [case report](docs/en/REPORT.md).

---

## Quick detection tips

```bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin           # never trust the inherited PATH
ldd /usr/bin/ls | grep -E "gcwrap|pprocps|fsnldev"   # rootkit hook loaded, even if ld.so.preload looks absent
awk '/HugePages_Total/{print $2}' /proc/meminfo      # non-zero without you configuring it
awk -F: '$7 ~ / $/ {print $1}' /etc/passwd           # shells with a trailing space (backdoor accounts)
cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs   # should list only crond
```

- Compare PIDs visible in `/proc` against every `cgroup.procs`: hidden processes show up only in the latter ([how](docs/en/ERADICATION-GUIDE.md#5-confirm-the-infection)).
- The rootkit hooks glibc, so a **musl container** (for example Alpine) with the host disk mounted and `--pid=host` sees the real state ([how](docs/en/ERADICATION-GUIDE.md#3-trusted-view-seeing-the-server-without-the-rootkit)).
- Stop `crond.service` (this kills its whole cgroup, including the hidden implant) **before** deleting files.
- Check `authorized_keys` on **system accounts** such as `ftp` and `lp`.

## Using the verification script

```bash
sudo bash verify-perfctl.sh
```

It only reads: it does not delete, move or change anything. It prints one `PASS` / `FAIL` / `WARN` line per check and exits with code `1` if any indicator is found, so it can run from `cron` or a monitoring agent. For best results run it twice: once on the host and once from the [trusted view](docs/en/ERADICATION-GUIDE.md#3-trusted-view-seeing-the-server-without-the-rootkit). A clean result does **not** prove the absence of compromise.

## Using the IOCs

The CSV has four columns: `type`, `value`, `description_en`, `description_es`. Types include `sha256`, `path`, `process`, `env_var`, `persistence`, `command`, `ssh_key_fp`, `ip`, `symptom`, `network` and `campaign_id`. Placeholders such as `<VICTIM_IP>` and `<PID>` stand for values that vary. Entries marked SENSITIVE refer to files that hold captured credentials: look for them, never share them.

## Scope and limits

- **No guarantee of total removal.** The rootkit tampers with `/proc`; absence of evidence is not evidence of absence. [Reinstalling remains the safest option](docs/en/ERADICATION-GUIDE.md#14-when-to-reinstall-dont-clean).
- Commands target **AlmaLinux/RHEL 8** with systemd and cgroups v1; [Debian/Ubuntu equivalents](docs/en/ERADICATION-GUIDE.md#appendix-a-debianubuntu-equivalents) are listed.
- The trusted-view technique requires a working Docker that is itself not compromised.
- Whether data was exfiltrated is **unknown**; local credential capture is confirmed.
- Not investigated: six kernel-crash reboots that preceded the discovery.

## Sharing and handling

Share **only binaries** and the IOC file. Do not publish the malware's working directory (`.xdiag`, `.atmp`): it holds terminal and PAM captures and server data. The `/usr/lib/vei` and `/usr/lib/exi` files and the campaign ID embed the victim's IP. See [What to keep for sharing](docs/en/ERADICATION-GUIDE.md#13-what-to-keep-for-sharing-anonymized).

## Feedback

Seen this variant, found a gap, or have a fix? Open an issue or a pull request. New hashes, paths or behaviors are especially welcome.

## References

- [Aqua Nautilus: perfctl, a stealthy malware targeting millions of Linux servers](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)
- [BleepingComputer: Linux malware perfctl behind years-long crypto mining campaign](https://www.bleepingcomputer.com/news/security/linux-malware-perfctl-behind-years-long-crypto-mining-campaign/)
- [Help Net Security](https://www.helpnetsecurity.com/2024/10/07/perfctl-perfcc-cryptomining-linux/) · [Security Affairs](https://securityaffairs.com/169351/malware/perfctl-malware-targets-misconfigured-linux-servers.html)
