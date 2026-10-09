# Eradication guide: perfctl (folddbus-send / tpm_dev_wq / libgcwrap variant) on Linux

**Language:** English · [Español](../es/GUIA-ERRADICACION.md)

Step-by-step guide to clean a Linux server running Docker that was infected by this variant **without reinstalling**, based on a real cleanup. It includes the exact commands, the verification after each phase, and the mistakes that made intermediate attempts fail.

> **Read it all before running anything.** Some steps are destructive or can cut your access. Do them in the order given.
> **Reinstalling is the safest option.** This guide is for when that is not possible, and it does not guarantee total removal. See [section 14](#14-when-to-reinstall-dont-clean).

The examples use AlmaLinux/RHEL 8 (`rpm`, `systemd`, cgroups v1). For Debian/Ubuntu see [Appendix A](#appendix-a-debianubuntu-equivalents). The placeholders `<ADMIN_IP>`, `<ADMIN_NET>` and `<MUSL_IMAGE>` are values you must replace. The companion script [`verify-perfctl.sh`](../../verify-perfctl.sh) is at the repository root.

---

## 0. What this malware does (to understand the order)

| Component | What it does | Consequence for cleanup |
|---|---|---|
| **Resident implant** (Go, 3 MB) | Lives inside the `crond.service` cgroup under a fake name (`s6-supervise s6rc-fdholder`). Every 10 s it rewrites the crontab, recreates files, changes `core_pattern`, and relaunches the miner. | **While it is alive, everything you delete comes back.** It must be killed first. |
| **Rootkit** `libgcwrap.so` (via `/etc/ld.so.preload`) | Hooks glibc: hides processes and files, and **captures credentials (PAM hook) and terminal sessions**. It hides itself. | With it active, `ps`, `top`, `ls`, `find` lie. You need a *trusted view* ([section 3](#3-trusted-view-seeing-the-server-without-the-rootkit)). |
| **Miner** (XMRig, 11 MB) | Copies in `/usr/bin/perfcc`, `/root/.config/cron/perfcc`, `/usr/lib/libpprocps.so`, `libfsnldev.so`. Reserves hugepages. | **All** copies must be removed. |
| **Fake `top`, `htop`, `ldd`, `crontab`, `df`, `mount`** | Binaries and scripts in `/usr/bin/.local/bin` that filter output. They are activated through a fake PATH in `/etc/profile`. | They hide the miner from whoever runs `top`. |
| **Backdoors** | `ftp` and `lp` accounts with the shell `"/sbin/nologin "` (trailing space, a copy of bash) and the attacker's SSH key; **a hidden Tor service**. | Review accounts and keys. |
| **Credential capture** | `data/pam/sshd.log` (PAM hook) and `data/tty/*.txt` (bash sessions) in its working directory. | **Assume the passwords typed on the server were leaked.** |
| **Proxyjacking** | `traffmonetizer` in `/dev/shm`. | Sells your bandwidth. |
| **Login persistence** | `/root/.bash_profile` runs `/bin/perfcc`; `/etc/cron.d/perfclean` runs `perfcc` every hour. | Review profiles and `cron.d`. |

---

## 1. Golden rules

1. **Do not reboot** until you are done. You would lose processes and state useful for analysis, and persistence reactivates at boot.
2. **Keep a second SSH session open** before touching `sshd` or the firewall.
3. **Do not trust the server's tools** while the rootkit is active (`ps`, `top`, `ls`, `find`, `lsof`, `ldd`, `crontab -l`).
4. **Kill the implant before deleting files.**
5. **Move to quarantine instead of deleting** (`mv`), so you can revert.
6. **Verify several times and over time.** The implant recreates files until the moment it dies: after killing it, check again. A single check is not enough.
7. **Pin the PATH** in every command: `export PATH=/usr/sbin:/usr/bin:/sbin:/bin`.
8. **Assume credentials are compromised** ([section 12](#12-after-cleaning-up)).

---

## 2. Preparation

```bash
# Connect as root and pin a safe PATH in ALL sessions
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# Working folder with restricted permissions
mkdir -p /root/forensics && chmod 700 /root/forensics

# Proof that the rootkit is active: if ldd lists libgcwrap, the hook is loaded even if ld.so.preload looks absent
ldd /usr/bin/ls | head
```

Have on hand:

- An **alternative access** to the server (the provider's VNC/KVM console), in case SSH is cut.
- A **musl image** available locally (for example `alpine` or `postgres:16-alpine`). If there is none, pull one *before* closing egress.

---

## 3. Trusted view: seeing the server without the rootkit

The rootkit uses `LD_PRELOAD`, which only affects **glibc** programs. A **musl** (Alpine) container with the host disk mounted and the host PID namespace **does not load the hook** and sees reality.

```bash
# Read-only
docker run --rm --pid=host --entrypoint sh -v /:/host:ro <MUSL_IMAGE> -c '
  echo "== preload =="; ls -la --full-time /host/etc/ld.so.preload; cat /host/etc/ld.so.preload
  echo "== malware libraries =="; ls -la /host/lib/libgcwrap.so /host/usr/lib/lib*.so 2>/dev/null
  echo "== search the whole disk by name =="
  find /host -xdev \( -name "*gcwrap*" -o -name "perfcc*" -o -name "pctl*" -o -name ".perf*" -o -name "folddbus*" \) 2>/dev/null
  echo "== real processes by CPU =="; ps -o pid,ppid,time,vsz,args | sort -k3 -r | head -15
'
```

> Times inside the container are shown in **UTC**. Account for the difference with the server clock.

**To modify things** (delete, `chattr`) use the same command with `-v /:/host` (without `:ro`) and `--cap-add LINUX_IMMUTABLE`:

```bash
docker run --rm --pid=host --cap-add LINUX_IMMUTABLE --entrypoint sh -v /:/host <MUSL_IMAGE> -c '...'
```

> This only works if Docker itself is not compromised. If the Docker binary or socket were tampered with, do not rely on this method.

---

## 4. Preserve the evidence

Before deleting, save what you need (the implant partially self-destructs and disguises itself):

```bash
Q=/root/forensics; cd $Q

# Binaries and files (restricted permissions: they may contain captured credentials)
umask 077
tar czf artifacts.tgz --ignore-failed-read \
  /usr/bin/.local /usr/bin/wbin /usr/bin/.atmp /usr/lib/vei /usr/lib/exi /etc/prdevid \
  "/usr/sbin/nologin " /tmp/.perf.c /tmp/.xdiag /tmp/.t.trf /tmp/k8t /tmp/k8s.run* \
  /dev/shm/.dmesg /dev/shm/.config /etc/cron.d/perfclean /var/spool/cron/root \
  /etc/profile /root/.bash_profile /etc/passwd /etc/shadow /etc/shells /var/ftp/.ssh /var/spool/lpd/.ssh

# Hashes of the binaries (use the trusted view if they are hidden)
sha256sum /usr/lib/libpprocps.so /usr/lib/libfsnldev.so /lib/libgcwrap.so /usr/bin/perfcc /usr/bin/folddbus-send 2>/dev/null > hashes.txt
```

**Do not execute anything you save.** If you are going to share samples, share **only the binaries**, not the working directory (`.xdiag`, `.atmp`): it contains terminal captures and server data.

---

## 5. Confirm the infection

Use the script from this repository (read-only). Run it **twice**: from the host and, if possible, from the trusted view.

```bash
bash verify-perfctl.sh
```

Quick manual indicators (if you cannot use the script):

```bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
ldd /usr/bin/ls | grep -E "gcwrap|pprocps|fsnldev"             # hook active
ls /etc/ld.so.preload 2>&1                                       # may be hidden
awk '/HugePages_Total/{print $2}' /proc/meminfo                  # != 0 without you configuring it
crontab -l | grep -E "perfcc|\.perf"                             # miner line
cat /etc/cron.d/* | grep -E "perfcc|perfclean"
grep -n -E "perfcc|/bin/\.local|AAZHDE|HZAA" /etc/profile /root/.bash_profile
awk -F: '$7 ~ / $/ {print $1}' /etc/passwd                       # shells with a trailing space
find / -xdev -name authorized_keys -not -path "/home/*" -not -path "/root/.ssh/*" 2>/dev/null
cat /proc/sys/kernel/core_pattern                                # does it point to /etc/coredumps/ ?
uptime                                                           # high load with "idle" CPU in top
```

**Detecting hidden processes** (compare `/proc` against the cgroups):

```bash
vis=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
cg=$(cat $(find /sys/fs/cgroup -name cgroup.procs) 2>/dev/null | sort -un)
comm -23 <(echo "$cg") <(echo "$vis")     # PIDs in a cgroup but absent from /proc
# A couple of short-lived PIDs (this very command's) is normal: repeat and look at the ones that persist.
```

**The hidden implant shows up in the `crond` cgroup** (or in whichever service it crawled into):

```bash
cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs      # should list ONLY crond's PID
for p in $(cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs); do
  echo "$p  exe=$(readlink /proc/$p/exe)"          # a hidden process's exe can still be read
done
```

If you see an exe in `/tmp`, `/dev/shm` or `/usr/bin/folddbus-send`, that is it.

---

## 6. Access containment

Do this **before** cleaning, so the attacker cannot get back in.

### 6.1 SSH

```bash
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)

# Keys only, root only (or your user), and only from your admin IP / network
sed -i -E 's/^#?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q '^AllowUsers' /etc/ssh/sshd_config || echo 'AllowUsers root' >> /etc/ssh/sshd_config   # adjust to the real user
cat >> /etc/ssh/sshd_config <<'EOF'

# --- Containment: only the admin IP/network ---
Match Address *,!<ADMIN_IP>,!<ADMIN_NET>
    DenyUsers *
EOF
sshd -t && echo "SYNTAX OK" && systemctl reload sshd
```

> `Match` must go at the **end** of the file. Before closing the current session, **open another in parallel** and check that you can log in:
> `ssh -o BatchMode=yes -o PreferredAuthentications=publickey user@server true`
> And check that a non-allowed IP is rejected: `sshd -T -C addr=8.8.8.8,user=root,host=x,laddr=1.1.1.1,lport=22 | grep -i denyusers`.

### 6.2 Firewall

- Restrict the SSH port to the admin IP/network **in the firewall**, not only in `sshd`.
- Close in the firewall the ports that should not be public: databases (5432/3306), admin panels (Portainer, 9100 metrics), Docker ports (2375/2376).
- An agent that mounts `/var/run/docker.sock` and the host `/` is equivalent to **remote root**: do not expose it.

---

## 7. Neutralize the resident implant

**This is the decisive step.** If you delete files without doing it, everything comes back within seconds.

### 7.1 Identify it (optional, to understand)

With `auditd` you can see who runs `crontab` every 10 s, together with its parent:

```bash
systemctl start auditd
auditctl -D
auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/crontab -F auid=-1 -k cw
sleep 30
# NOTE: ausearch without --input-logs hangs waiting for stdin when there is no TTY
ausearch --input-logs -k cw -i | grep -a "type=SYSCALL" | head
grep -a 'key="cw"' /var/log/audit/audit.log | grep -o -E " ppid=[0-9]+" | sort -u
```

If the `ppid` does not appear in `/proc`, it is hidden: look for it in the `cgroup.procs` files ([section 5](#5-confirm-the-infection)).

### 7.2 Kill it

Stopping the service **kills its whole cgroup**, including processes you cannot see:

```bash
systemctl kill -s SIGKILL crond      # or the service where the implant is
systemctl stop crond
cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs      # must be empty
```

> **Do not start `crond` yet.** Clean the files first ([sections 8-10](#8-remove-the-rootkit)), so the new `crond` does not run `perfcc`. If the implant were in another cgroup (a user session, another service), use `systemctl kill` on that service or `loginctl terminate-session <id>`.

Also kill any remaining process with a suspicious executable:

```bash
for p in /proc/[0-9]*; do e=$(readlink $p/exe 2>/dev/null); case "$e" in /tmp/*|/dev/shm/*|/var/tmp/*|*deleted*|*folddbus*|*perfcc*|*/.perf.c/*) echo "${p#/proc/} $e";; esac; done
# kill -9 <PID> on the ones that belong to the malware (do not kill VS Code Server or other processes of yours)
```

And the ones in the SSH sessions that got infected at login (launched by `/root/.bash_profile`): close those sessions and log in again after cleaning `.bash_profile`.

---

## 8. Remove the rootkit

With the implant already dead:

```bash
docker run --rm --pid=host --cap-add LINUX_IMMUTABLE --entrypoint sh -v /:/host <MUSL_IMAGE> -c '
  # Remove the immutable attribute
  chattr -i /host/etc/ld.so.preload /host/lib/libgcwrap.so /host/usr/lib/libgcwrap.so \
            /host/usr/lib/libpprocps.so /host/usr/lib/libfsnldev.so 2>/dev/null
  # ld.so.preload first (so the host tools stop loading the hook)
  rm -f /host/etc/ld.so.preload
  rm -f /host/lib/libgcwrap.so /host/usr/lib/libgcwrap.so /host/lib64/libgcwrap.so
  rm -f /host/usr/lib/libpprocps.so /host/usr/lib/libfsnldev.so /host/usr/lib/libfsnkdev.so
  # Immutable attributes in critical paths (if any are left)
  for d in /host/etc /host/usr/bin /host/usr/sbin /host/usr/lib /host/usr/lib64 /host/root /host/tmp /host/var/spool; do
    lsattr -R $d 2>/dev/null | grep -E "^[-a-zA-Z]{4}i"
  done
'
ldconfig                                    # regenerate ld.so.cache (the cache also referenced the libraries)
ldd /usr/bin/ls | grep -E "gcwrap|pprocps|fsnldev" || echo "hook unloaded"
```

---

## 9. Remove the malware files

Move to quarantine. Check with the trusted view whether the rootkit is still active; if you already removed it, the normal tools see correctly.

```bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
Q=/root/forensics/quarantine; mkdir -p $Q; chmod 700 $Q

# Remove immutable flags from what follows
chattr -R -i /usr/bin/.local /usr/bin/.atmp /tmp/.perf.c /tmp/.xdiag /dev/shm/.dmesg /dev/shm/.config \
             /etc/cron.d/perfclean "/usr/sbin/nologin " 2>/dev/null

# Miner and implant binaries
mv /usr/bin/perfcc /usr/bin/folddbus-send /usr/bin/kbush /usr/bin/kkbush $Q/ 2>/dev/null
mv /root/.config/cron $Q/root_config_cron 2>/dev/null

# Working directories
mv /tmp/.perf.c /tmp/.xdiag /tmp/.t.trf /tmp/k8t /tmp/k8s.run* /tmp/daisp /tmp/rsr /tmp/go $Q/ 2>/dev/null
mv /usr/bin/.atmp /usr/bin/.local /usr/bin/wbin $Q/ 2>/dev/null           # /bin is a symlink to /usr/bin
mv /dev/shm/.dmesg /dev/shm/.config $Q/ 2>/dev/null                       # tmpfs: emptied on reboot, but clean it now

# Identification files
mv /usr/lib/vei /usr/lib/exi /etc/prdevid $Q/ 2>/dev/null

# Cron persistence
mv /etc/cron.d/perfclean $Q/ 2>/dev/null
crontab -l > $Q/crontab.orig
crontab -l | grep -v -E "perfcc|/tmp/\.perf" | crontab -               # check that only YOUR jobs remain
crontab -l

# The fake shell (a copy of bash with a trailing space)
mv "/usr/sbin/nologin " $Q/nologin_trojan 2>/dev/null
```

> The fake `top/htop/ldd/crontab/df/mount` are inside `/usr/bin/.local`; they have already been moved.

---

## 10. Restore the configuration

### 10.1 Login profiles

```bash
cp -a /etc/profile $Q/etc_profile.infected; cp -a /root/.bash_profile $Q/bash_profile.infected

sed -i '\|^export PATH=/bin/.local/bin:$PATH$|d' /etc/profile      # fake PATH
sed -i '/perfcc/d' /root/.bash_profile                              # malware launcher
grep -n -E "perfcc|/bin/\.local|wbin|AAZHDE|HZAA" /etc/profile /root/.bash_profile /root/.bashrc /etc/bashrc /etc/profile.d/* || echo "profiles clean"

# Compare /etc/profile against the original package
rpm -V setup          # only the mtime (T) should differ. If the content differs, review by hand.
bash -lc 'echo $PATH'  # must NOT start with /bin/.local/bin
```

### 10.2 Accounts, shells and keys

```bash
# Valid system shells
printf "/bin/sh\n/bin/bash\n/usr/bin/sh\n/usr/bin/bash\n/sbin/nologin\n/usr/sbin/nologin\n" > /etc/shells

# System accounts used as backdoors
for u in ftp lp; do usermod -s /sbin/nologin $u; passwd -l $u; done
awk -F: '$7 ~ / $/ {print "BAD:", $1}' /etc/passwd        # must print nothing
awk -F: '$3==0 {print $1}' /etc/passwd                      # only root

# Keys of system accounts
mv /var/ftp/.ssh /var/spool/lpd/.ssh $Q/ 2>/dev/null
find / -xdev -name authorized_keys -not -path "/proc/*" -not -path "*/forensics*" 2>/dev/null

# Root's keys: leave ONLY yours
ssh-keygen -lf /root/.ssh/authorized_keys     # recognize each one; delete any that is not yours
```

> The fingerprint of the attacker's RSA-4096 key is `SHA256:kKI/tpGGK0vklmw0DCIzTYVlbklDBvCMXGQsb/nShq8`.

### 10.3 Kernel and resources

```bash
sysctl -w vm.nr_hugepages=0
sysctl -w kernel.core_pattern='|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e'   # RHEL 8 default
cat /proc/sys/kernel/core_pattern
```

### 10.4 Services

```bash
systemctl start crond && systemctl is-active crond
cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs | wc -l     # must be 1
```

---

## 11. Verification

Run the script and check by hand. **Repeat after 5 minutes, 1 hour and 24 hours.**

```bash
bash verify-perfctl.sh           # expected: FAIL=0
```

Expected, one by one:

| Check | Expected result |
|---|---|
| `ls /etc/ld.so.preload` | Does not exist |
| `ldd /usr/bin/ls` | No `gcwrap` / `pprocps` / `fsnldev` |
| `crontab -l`, `ls /etc/cron.d` | Only your jobs; no `perfcc` or `perfclean` |
| `grep perfcc /etc/profile /root/.bash_profile` | No matches |
| `awk '/HugePages_Total/{print $2}' /proc/meminfo` | 0 |
| `cat /proc/sys/kernel/core_pattern` | Does not point to `/etc/coredumps/` |
| `cat …/crond.service/cgroup.procs \| wc -l` | 1 |
| PIDs in cgroups but not in `/proc` | None that persist |
| Processes with an exe in `/tmp`, `/dev/shm`, `deleted` | None |
| `authorized_keys` on system accounts | None |
| `rpm -V` (critical packages) | No differences in binaries |
| `ls /usr/bin/.local /usr/bin/wbin /usr/bin/.atmp /tmp/.perf.c /tmp/.xdiag /dev/shm/.dmesg` | They do not exist |
| Load (`uptime`) and real CPU (difference of `/proc/stat`) | Normal |

**Measure CPU as a difference**, not as a cumulative value: the "since boot" percentage that some dashboards show stays high for hours after a cleanup.

```bash
a=($(head -1 /proc/stat)); sleep 5; b=($(head -1 /proc/stat)); ta=0; tb=0
for i in 1 2 3 4 5 6 7; do ta=$((ta+${a[$i]})); tb=$((tb+${b[$i]})); done
awk -v ia=${a[4]} -v ib=${b[4]} -v ta=$ta -v tb=$tb 'BEGIN{printf "%.1f%%\n",(1-(ib-ia)/(tb-ta))*100}'
```

**If something reappears, an implant is still alive**: go back to [section 7](#7-neutralize-the-resident-implant) and look in the `cgroup.procs` of every service and session.

---

## 12. After cleaning up

### 12.1 Assume credentials are compromised

This malware **captures credentials** (PAM hook → `data/pam/sshd.log`) and **terminal sessions** (`data/tty/*.txt`) during the whole infection period. Rotate **everything used or stored on the server**:

- The root password and that of any user who logged in (over SSH or console) during the compromise.
- The server's SSH keys (the private ones stored on it) and any that give access to other systems.
- Database, Docker/registry and panel credentials (Portainer, etc.).
- `.env` files, application secrets, API tokens and keys in the containers' environment variables.
- If you reuse passwords on other services, change those too.

### 12.2 Minimum hardening

- SSH with keys only and restricted by network ([section 6](#6-access-containment)). Install `fail2ban` or equivalent.
- Close unneeded ports in the firewall ([section 6.2](#62-firewall)).
- Mount `/tmp`, `/var/tmp` and `/dev/shm` with `noexec,nosuid,nodev`.
- Apply security updates (`dnf update --security`).
- Do not mount `docker.sock` or the host `/` in containers unless indispensable.

### 12.3 Continuous monitoring

```bash
systemctl enable --now auditd
auditctl -w /etc/ld.so.preload -p wa -k mw_preload
auditctl -w /var/spool/cron -p wa -k mw_cron
auditctl -w /etc/cron.d -p wa -k mw_cron
auditctl -w /root/.ssh -p wa -k mw_ssh
auditctl -w /etc/passwd -p wa -k mw_passwd
auditctl -w /etc/profile -p wa -k mw_profile
auditctl -w /root/.bash_profile -p wa -k mw_profile
auditctl -w /usr/lib -p w -k mw_lib
auditctl -w /usr/bin -p w -k mw_bin
auditctl -a always,exit -F arch=b64 -S execve -F dir=/tmp -k mw_exec_tmp
auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/crontab -F auid=-1 -k mw_crontab
# To make them survive a reboot, put them in /etc/audit/rules.d/*.rules and run augenrules --load
```

And schedule the verification script (read-only) every hour with a `cron` job that **sends an alert** if it returns a non-zero code.

### 12.4 Reboot

When everything is clean and the evidence is saved, **reboot** once, in a quiet window, and run the script again. If something reappears at boot, there is persistence you did not find (a systemd unit, `initrd`, a module, a timer). In that case: reinstall.

---

## 13. What to keep for sharing (anonymized)

- Share **only binaries** (miner, implant, rootkit, fake `top`/`ldd`), never the working directory.
- In reports, replace IPs, hostnames, domains, container/project names and any credential.
- The `vei` and `exi` files and the campaign ID (`poa_<IP>`) contain the victim's IP.
- The `data/tty` and `data/pam` captures are **sensitive data**: do not upload them or paste them into tickets.

---

## 14. When to reinstall (don't clean)

Reinstall from a clean image if **any** of these applies:

- `rpm -V` (or `debsums`) shows differences in **binaries** of critical packages (glibc, coreutils, openssh, systemd, bash, sudo, shadow-utils).
- There are **unknown kernel modules** (`lsmod`), an unexplained `tainted != 0`, or eBPF programs you do not recognize.
- Something **reappears after a reboot** and you cannot find where it comes from.
- You cannot identify the entry vector and the server holds high-value secrets.
- The implant was there for **weeks** (this variant was ~63 hours), or there are signs of lateral movement to other machines.
- You are not certain you found everything: the rootkit tampers with `/proc`, so the absence of evidence is not evidence of absence.

If you reinstall: restore **data only** (database dumps, volumes), not binaries or configuration; rotate every secret; and review the machines you used to administer the server.

---

## 15. Mistakes that broke intermediate attempts

1. **Deleting without killing the implant.** Everything reappeared within seconds. The implant lived in the `crond` cgroup.
2. **Trusting `ps`/`top`/`ls`.** With `libgcwrap` loaded they showed neither the miner nor the files.
3. **`rm` without `chattr -i`.** It gave "Operation not permitted" on `ld.so.preload` and the libraries.
4. **Forgetting `ldconfig`.** `ld.so.cache` kept listing the malware libraries.
5. **Not verifying again after killing the implant.** More than 20 minutes passed between a first "cleanup" and the implant's death, and the implant recreated `ld.so.preload`, `/etc/profile`, `/root/.bash_profile`, `/etc/cron.d/perfclean`, `.local`, `vei`, `exi`, `nologin ` and keys in `lp`. A later review found the leftovers. **Always verify after the implant is dead.**
6. **`ausearch` without `--input-logs`** hangs waiting for stdin and piles up processes.
7. **A `ps | grep crontab` sampler detects itself**: save the script in a file and use `pgrep -x`.
8. **Searching only by name.** The implant called itself `s6-supervise` and `dockerd`. Comparing `exe` (`readlink /proc/PID/exe`) with the declared name exposed the disguise.
9. **Trusting a cumulative CPU indicator** (computed since boot) to decide whether the miner was still active.
10. **Locking out your own IP.** If you restrict SSH by IP and your IP is dynamic, you lock yourself out. Keep an alternative path (a VPN) or the provider's console.

---

## Appendix A: Debian/Ubuntu equivalents

| RHEL/AlmaLinux | Debian/Ubuntu |
|---|---|
| `rpm -V package` | `debsums -s package` (install `debsums`) or `dpkg -V package` |
| `rpm -qf file` | `dpkg -S file` |
| Service `crond` | Service `cron` (`systemctl kill -s SIGKILL cron`) |
| `dnf update --security` | `unattended-upgrade` / `apt upgrade` |
| `/etc/sysconfig/...` | `/etc/default/...` |
| Default `core_pattern` | `|/usr/share/apport/apport ...` (Ubuntu) or `core` |
| `/usr/lib/systemd/system` | `/lib/systemd/system` |

## Appendix B: References

- [Aqua Nautilus: perfctl](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/linux-malware-perfctl-behind-years-long-crypto-mining-campaign/)
- [Help Net Security](https://www.helpnetsecurity.com/2024/10/07/perfctl-perfcc-cryptomining-linux/)
- [Security Affairs](https://securityaffairs.com/169351/malware/perfctl-malware-targets-misconfigured-linux-servers.html)
