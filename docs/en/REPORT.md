# A perfctl variant with `trufflehog` and system-account backdoors: analysis of a real case

**Language:** English · [Español](../es/INFORME.md)
**TLP:CLEAR** · AlmaLinux 8.10 server (kernel 4.18) · ~63 hours of compromise · cleaned without reinstalling

> This document is anonymized: it contains no organization names, hostnames, victim IPs or credentials. The IOCs are in a separate CSV file: [`iocs/perfctl-folddbus-iocs.csv`](../../iocs/perfctl-folddbus-iocs.csv).
> For the procedure itself, go to the [eradication guide](ERADICATION-GUIDE.md).

---

## Summary

A Linux server running Docker showed hugepages reserved for no obvious reason and a load that did not match the CPU usage displayed. The cause was a **Monero miner with a rootkit from the perfctl family**, installed as root. The variant matches what [Aqua Nautilus](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/) described, but adds elements we did not see in public reports: a resident Go binary that masquerades as `s6-supervise` inside the `crond` cgroup, execution of **`trufflehog`**, **credential and terminal-session capture**, a **hidden Tor service**, and **system accounts (`ftp`, `lp`) with a copy of bash as their shell** and the attacker's SSH key.

It was cleaned without reinstalling. The initial access vector was not determined.

## How it showed up

- `vm.nr_hugepages` at 131 (later 607) even though a `/etc/sysctl.d/*` file set it to 0. The miner changes it at runtime.
- Load of 10-16 while `top` showed 60-90% idle CPU.
- A remote-monitoring tool showing a sustained ~55% CPU (a cumulative-since-boot calculation that carried the miner's period).
- Six kernel-crash reboots in two days (not investigated).

## Matches with documented perfctl

| Documented | Observed |
|---|---|
| `httpd` disguise | Process `httpd -j` |
| `/root/.config/cron/perfcc`, `/usr/bin/perfcc` | Present, plus an hourly line in root's crontab |
| `/usr/lib/libpprocps.so`, `libfsnkdev.so` | `libpprocps.so` and `libfsnldev.so` (copies of the miner, 11 MB) |
| `libgcwrap.so` rootkit via `/etc/ld.so.preload` | Present, with `chattr +i` |
| Fake `top`, `ldd`, `crontab` in `~/.local/bin`, `AAZHDE` variable | Present in `/usr/bin/.local/bin`, with the `HZAA` and `AAZHDE` variables |
| `.xdiag` directory | `/usr/bin/.atmp/tmp/.applocal.xdiag` and `/tmp/.xdiag` |

## What is new in this variant

1. **Resident Go implant inside the `crond.service` cgroup.** It was called `s6-supervise s6rc-fdholder`, but its real executable was `/tmp/.perf.c/s6-supervise` (a copy of the 11 MB binary). It did not show up in `ps` nor in the `/proc` listing, but it did in `/sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs`. Every 10 seconds it ran:
   ```
   find /var/spool/cron/crontabs -type f | grep cron | grep '/root$' | xargs cat
   (crontab -l | grep -v -e perfcc -e /tmp/.perf; echo '11 * * * * /root/.config/cron/perfcc') | crontab -
   echo '/etc/coredumps/%e.%p.%u.%t' > /proc/sys/kernel/core_pattern
   ```
2. **A second component disguised as `dockerd`** (executable `/usr/bin/folddbus-send`, mode 777), launched with `nohup folddbus-send <token>` from `/tmp` and the variables `XVEIL=poa`, `APPROC='/usr/bin/dockerd …'`, `AAPCRK`.
3. **`trufflehog`** run from `/usr/bin/.atmp/tmp/.applocal.xdiag/` to look for secrets. The staging area (`cloud_meta.txt`, `files_other/`, `files_th/`) was empty and the cloud-metadata query returned a 404.
4. **Backdoors in system accounts:** `ftp` and `lp` with the shell `"/sbin/nologin "` (name with a **trailing space**) that was a **copy of `/usr/bin/bash`**, plus `authorized_keys` with the same RSA-4096 key of the attacker. The aliases `kbush` and `kkbush` also pointed to bash.
5. **"Hidden Docker":** scripts in `/usr/bin/wbin/` imitating Docker/containerd binaries with `env AAZHDE=1`, and a base64 downloader that used a socket `/bin/wbin/run/docker.socket` and `registry.docker.io`. The fake `df` and `mount` filtered any line containing `/wbin/`.
6. **Login persistence:** `/root/.bash_profile` with `test -x /bin/perfcc && FPROF=p /bin/perfcc`, and `/etc/profile` with `export PATH=/bin/.local/bin:$PATH`.
7. **Immutable attributes:** `ld.so.preload`, `libgcwrap.so`, `libfsnldev.so` and `libpprocps.so` had `chattr +i`, as did files inside `.atmp`.
8. **Credential and session capture.** The malware's working directory (`/tmp/.xdiag`, ~41 MB) held `data/pam/sshd.log` (a `pam_authenticate` hook, consistent with what is described for `libgcwrap.so`) and `data/tty/-bash.*.txt` (24 captures of bash sessions between the first and last day of the compromise). The PAM file was last modified during a password login made on the day of the cleanup. **Assume that the passwords used on the server and what was typed in its terminals during the period were exposed.**
9. **Hidden Tor service and Tor client** (`tordata/`, `torrc-*`, an `hs.txt` file with the hidden-service identifier, and the socket `int/.per.s`), usable as an access and communication channel. No traffic to the Tor destinations listed in public reports was seen during the observation window, but full network traffic was not captured.
10. **Proxyjacking:** `/dev/shm/.config/traffmonetizer/cli_device_ids.json`. Consistent with the bandwidth-monetization apps described in the reports.
11. **PID tracking in `/dev/shm/.dmesg/{pds,ino}`**, one file per malware process.
12. **Extra persistence via `cron.d`:** `/etc/cron.d/perfclean` (`9 * * * * root perfcc`), in addition to the line in root's crontab.
13. **An empty setuid file** `apxj` (`-rwsr-sr-t`) and markers `/tmp/daisp`, `/tmp/rsr`, `/tmp/go/imports`.

> Note on the staging directory: `/usr/bin/.atmp/tmp/.applocal.xdiag/` kept the dropper's original package (`trunk.<hash>_<IP>_.sx2.tar.gz`) and an unmodified `trufflehog` binary.

## What worked for detection

- **An Alpine container with the host disk mounted and `--pid=host`.** The rootkit hooks glibc, so a musl-based container (for example `postgres:16-alpine`) saw `ld.so.preload`, the library and the hidden process. With `--cap-add LINUX_IMMUTABLE` it allowed `chattr -i` and deleting them.
- **Reading `cgroup.procs` instead of `/proc`.** Comparing the number of visible PIDs with those of all `cgroup.procs` gave away hidden processes.
- **`auditd` with an `execve` rule on `/usr/bin/crontab`** and the parent chain, which revealed the 10-second rewrite loop and the implant's commands.
- **`ldd /usr/bin/ls`** showed `/lib/libgcwrap.so` loaded even when `/etc/ld.so.preload` was hidden.
- **`rpm -V`** on critical packages to confirm the system binaries were intact, and therefore that cleaning without reinstalling was viable.

## Cleanup (the order that worked)

1. Close access (SSH keys only, IP list, `AllowUsers root`).
2. Stop `crond` (kills its whole cgroup, including the hidden implant) and start a clean one.
3. Remove `chattr +i` and delete `ld.so.preload`, `libgcwrap.so`, the miner copies and the `.perf.c`, `.atmp`, `wbin`, `.local` directories.
4. Restore crontab, `/etc/profile`, `.bash_profile`, `core_pattern`, `/etc/shells`, `vm.nr_hugepages=0`.
5. Return `ftp` and `lp` to the real `/sbin/nologin`, lock them and delete their `authorized_keys`.
6. Regenerate `ld.so.cache` with `ldconfig`.
7. `auditd` rules on `ld.so.preload`, cron, `~/.ssh`, `/etc/passwd`, profiles and `execve` from `/tmp`, then monitoring.

**Verify after the implant is dead.** Between a first cleanup and the implant's death, it recreated `ld.so.preload`, `/etc/profile` (fake PATH), `/root/.bash_profile` (`perfcc`), `/etc/cron.d/perfclean`, `/usr/bin/.local`, `/usr/lib/vei|exi`, the fake `lp` shell and its SSH key. Those leftovers were only found when a full verification script was run hours later. A spot check with a handful of indicators would not have found them.

**Trap to avoid:** killing the visible processes and deleting files *without* stopping the resident implant makes everything come back in seconds. Until the `crond` cgroup was stopped, the rootkit, the libraries and the cron line kept reappearing.

## What is not known

- **The entry vector.** Polkit was patched (CVE-2021-4034) and there was no RocketMQ. There were several exposed services (a database and a Docker management agent with the Docker socket and the host `/` mounted) and constant SSH brute force.
- **Whether data was exfiltrated.** `trufflehog` ran as root for hours, but the staging area was empty. There was also local capture of credentials and terminal sessions; it is unknown whether any of it was sent out.
- **The cause of the kernel crashes.**
- **A guarantee of total cleanliness.** The original report's recommendation, reinstalling, is still the safest.

## Recommendations

- Do not expose administration services or databases to the Internet. An agent that mounts `/var/run/docker.sock` and the host `/` is equivalent to remote root.
- SSH with keys only, restricted by network, plus `fail2ban`.
- Mount `/tmp` and `/dev/shm` with `noexec,nosuid`.
- Watch `ld.so.preload`, `~/.bash_profile`, `/etc/profile` and root's crontab with `auditd`.
- Check `/etc/passwd` for shells with spaces or outside `/etc/shells`, and `authorized_keys` on system accounts.
- Compute CPU as the difference between two `/proc/stat` readings, not the cumulative value.
- After a confirmed infection: rebuild from a clean image, rotate every secret, and review the machine you administer from.

## Guide and tools

- [ERADICATION-GUIDE.md](ERADICATION-GUIDE.md): detailed procedure, with commands, verification and criteria for reinstalling.
- [`verify-perfctl.sh`](../../verify-perfctl.sh): **read-only** verification of all known indicators (exits with code 1 if it finds any).
- [`iocs/perfctl-folddbus-iocs.csv`](../../iocs/perfctl-folddbus-iocs.csv): indicators of compromise (English and Spanish descriptions).

## References

- [Aqua Security: perfctl, a stealthy malware targeting millions of Linux servers](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)
- [BleepingComputer: Linux malware perfctl behind years-long crypto mining campaign](https://www.bleepingcomputer.com/news/security/linux-malware-perfctl-behind-years-long-crypto-mining-campaign/)
- [Help Net Security: Linux systems targeted with stealthy "Perfctl" cryptomining malware](https://www.helpnetsecurity.com/2024/10/07/perfctl-perfcc-cryptomining-linux/)
- [Security Affairs: New Perfctl malware targets Linux servers](https://securityaffairs.com/169351/malware/perfctl-malware-targets-misconfigured-linux-servers.html)
