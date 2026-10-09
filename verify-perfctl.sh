#!/bin/bash
# verify-perfctl.sh - READ-ONLY check for indicators of the perfctl variant
# (folddbus-send / tpm_dev_wq / libgcwrap). It does not modify or delete anything.
#
# Usage (as root):   bash verify-perfctl.sh
# Best results: run it twice, once on the host and once from a musl container with the host
# mounted (see "Trusted view" in the eradication guide), because the rootkit can lie to
# glibc tools on the host.
#
# Output: one PASS / FAIL / WARN line per check plus a summary.
# Exit code: 0 if there are no FAIL lines, 1 otherwise, 2 if not run as root.
#
# Spanish docs: docs/es/GUIA-ERRADICACION.md (output of this script is in English).

export PATH=/usr/sbin:/usr/bin:/sbin:/bin   # avoid poisoned PATHs (e.g. /bin/.local/bin)
FAIL=0; WARN=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %b\n' "$1"; FAIL=$((FAIL+1)); }
warn() { printf 'WARN  %b\n' "$1"; WARN=$((WARN+1)); }

[ "$(id -u)" = 0 ] || { echo "Run as root."; exit 2; }

# --- 1. LD_PRELOAD rootkit -----------------------------------------------------------------
if [ -e /etc/ld.so.preload ]; then fail "/etc/ld.so.preload exists: $(cat /etc/ld.so.preload 2>/dev/null)"; else pass "/etc/ld.so.preload does not exist"; fi
if ldd /usr/bin/ls 2>/dev/null | grep -q -E "gcwrap|libpprocps|libfsnldev"; then
  fail "ldd /usr/bin/ls loads a malware library (the hook is active even if ld.so.preload looks absent)"
else pass "ldd /usr/bin/ls shows no malware libraries"; fi
for f in /lib/libgcwrap.so /usr/lib/libgcwrap.so /lib64/libgcwrap.so /usr/lib/libpprocps.so /usr/lib/libfsnldev.so /usr/lib/libfsnkdev.so; do
  [ -e "$f" ] && fail "found $f"
done
ldconfig -p 2>/dev/null | grep -q -E "gcwrap|pprocps|fsnldev|fsnkdev" && fail "ld.so.cache references malware libraries (run ldconfig after deleting them)"

# --- 2. Known files and directories --------------------------------------------------------
for p in /usr/bin/perfcc /bin/perfcc /root/.config/cron/perfcc /usr/bin/folddbus-send /tmp/.perf.c /tmp/.t.trf /tmp/k8t \
         /usr/bin/.atmp /usr/bin/.local /bin/.local /usr/bin/wbin /usr/bin/kbush /usr/bin/kkbush /usr/lib/vei /usr/lib/exi /etc/prdevid \
         /etc/cron.d/perfclean /dev/shm/.dmesg /dev/shm/.config/traffmonetizer /tmp/daisp /tmp/rsr /tmp/go/imports /tmp/.xdiag; do
  [ -e "$p" ] && fail "found $p"
done
ls /tmp/k8s.run* >/dev/null 2>&1 && fail "found markers /tmp/k8s.run*"
[ -e "/usr/sbin/nologin " ] && fail "found '/usr/sbin/nologin ' (trailing space): backdoor shell"
pass "(end of known-path search)"

# --- 3. Persistence: cron and profiles -----------------------------------------------------
if crontab -l 2>/dev/null | grep -q -E "perfcc|/tmp/\.perf|\.config/cron"; then fail "root crontab contains perfcc"; else pass "root crontab has no perfcc"; fi
grep -l -r -s -E "perfcc|perfclean|\.perf\.c" /var/spool/cron /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/crontab 2>/dev/null | grep -q . \
  && fail "perfcc referenced in system cron"
for f in /etc/profile /etc/bashrc /etc/bash.bashrc /root/.bash_profile /root/.bashrc /root/.profile /etc/profile.d/*; do
  [ -f "$f" ] && grep -q -E "perfcc|/bin/\.local|wbin|AAZHDE|HZAA" "$f" 2>/dev/null && fail "contaminated profile: $f"
done
pass "(end of profile review)"
for u in /etc/systemd/system /usr/lib/systemd/system /run/systemd/system; do
  grep -l -r -s -E "perfcc|folddbus|\.perf\.c|libgcwrap" "$u" 2>/dev/null | grep -q . && fail "systemd unit references the malware in $u"
done

# --- 4. Accounts and SSH keys --------------------------------------------------------------
badshell=$(awk -F: '$7 ~ / $/ {print $1}' /etc/passwd)
[ -n "$badshell" ] && fail "accounts whose shell ends in a space: $badshell" || pass "no shell with a trailing space"
notin=$(awk -F: '$7!="" {print $7}' /etc/passwd | sort -u | grep -v -E '^/(bin|sbin)/(sync|halt|shutdown)$' | while read -r s; do grep -qxF "$s" /etc/shells || echo "[$s]"; done | tr '\n' ' ')
[ -n "$notin" ] && warn "shells in /etc/passwd that are not in /etc/shells: $notin"
sys_keys=$(find / -xdev -name authorized_keys -not -path "/proc/*" -not -path "/root/.ssh/*" -not -path "/home/*" -not -path "*/forensics*" -not -path "*/quarantine*" 2>/dev/null)
[ -n "$sys_keys" ] && fail "authorized_keys outside root and /home (system accounts): $sys_keys" || pass "no authorized_keys on system accounts"
if find / -xdev -name 'authorized_keys*' -not -path "/proc/*" -not -path "*/forensics*" -not -path "*/quarantine*" 2>/dev/null | xargs -r -n1 ssh-keygen -lf 2>/dev/null | grep -q "kKI/tpGGK0vklmw0DCIzTYVlbklDBvCMXGQsb/nShq8"; then
  fail "attacker SSH key present (SHA256:kKI/tpGGK0vklmw0DCIzTYVlbklDBvCMXGQsb/nShq8)"; else pass "attacker key not found"; fi
for f in /root/.ssh/authorized_keys; do [ -f "$f" ] && echo "INFO  root authorized keys: $(grep -c -E '^(ssh|ecdsa|sk-)' "$f")  (confirm that ALL of them are yours)"; done
awk -F: '$3==0 {print $1}' /etc/passwd | grep -vx root | grep -q . && fail "other accounts with UID 0"

# --- 5. Kernel / sysctl effects ------------------------------------------------------------
hp=$(awk '/HugePages_Total/ {print $2}' /proc/meminfo)
[ "${hp:-0}" != 0 ] && fail "HugePages_Total=$hp (the miner reserves hugepages; an indicator if you did not configure them)" || pass "HugePages_Total=0"
cp=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
case "$cp" in /etc/coredumps/*) fail "core_pattern tampered with: $cp";; *) pass "core_pattern looks normal: $cp";; esac
[ "$(cat /proc/sys/kernel/tainted 2>/dev/null)" != 0 ] && warn "kernel tainted=$(cat /proc/sys/kernel/tainted) (check lsmod)"

# --- 6. Processes: suspicious executables and hidden processes -------------------------------
sus=""
for p in /proc/[0-9]*; do
  pid=${p#/proc/}; e=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$e" in /tmp/*|/dev/shm/*|/var/tmp/*|*"(deleted)"*|*folddbus*|*perfcc*|*/.perf.c/*|/usr/bin/.*) sus="$sus\n  pid=$pid exe=$e";; /root/.vscode-server/*) ;; /root/.*) sus="$sus\n  pid=$pid exe=$e";; esac
done
[ -n "$sus" ] && fail "processes with a suspicious executable:$(printf '%b' "$sus")" || pass "no process runs from /tmp, /dev/shm, hidden paths or a deleted file"

for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -q -E '^(XVEIL|AAPCRK|APPROC|AAZHDE|HZAA)=' && fail "process $pid has malware environment variables ($(readlink "$p/exe" 2>/dev/null))"
done

ps -eo args 2>/dev/null | grep -i -E "traffmonetizer|bitping|repocket|earnfm|earn\.fm|speedshare|honeygain|packetstream|peer2profit" | grep -v grep | grep -q . \
  && fail "proxyjacking process running (traffmonetizer/bitping/repocket/etc.)" || pass "no known proxyjacking process"

# PIDs that exist in some cgroup but are missing from the /proc listing (hidden processes).
# Re-checked after 1 s to discard short-lived processes (including this script's own).
cg=$(cat $(find /sys/fs/cgroup -name cgroup.procs 2>/dev/null) 2>/dev/null | sort -un)
vis=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
cand=$(comm -23 <(echo "$cg") <(echo "$vis"))
sleep 1
hidden=""
for pid in $cand; do
  if kill -0 "$pid" 2>/dev/null && ! ls /proc | grep -qx "$pid"; then hidden="$hidden $pid"; fi
done
[ -n "$hidden" ] && fail "processes alive in cgroups but hidden from /proc:$hidden" || pass "no persistent hidden process (cgroup.procs vs /proc)"

n=$(cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs 2>/dev/null | wc -l)
[ "$n" -gt 1 ] 2>/dev/null && fail "crond.service has $n processes in its cgroup (should be 1; the implant hid there)" || pass "crond.service cgroup has 1 process"
[ -d /sys/fs/cgroup/systemd/system.slice/cron.service ] && {
  n=$(cat /sys/fs/cgroup/systemd/system.slice/cron.service/cgroup.procs | wc -l); [ "$n" -gt 1 ] && warn "cron.service has $n processes (Debian/Ubuntu: check them)"; }

# --- 7. Immutable attributes in system paths -----------------------------------------------
imm=$(lsattr -R /etc /usr/lib /usr/lib64 /usr/bin /usr/sbin /lib /lib64 /root /tmp /var/spool /var/ftp 2>/dev/null | grep -E '^[-a-zA-Z]{4}i' | head -20)
[ -n "$imm" ] && fail "immutable files (chattr +i) in system paths:\n$imm" || pass "no immutable files in system paths"

# --- 8. Package integrity ------------------------------------------------------------------
if command -v rpm >/dev/null; then
  all=$(rpm -V --nomtime glibc coreutils util-linux procps-ng findutils bash openssh openssh-server systemd cronie sudo shadow-utils audit setup 2>&1)
  out=$(echo "$all" | grep -v -E '^\S+\s+c /' )
  cfg=$(echo "$all" | grep -E '^\S+\s+c /' )
  [ -n "$out" ] && fail "rpm -V reports differences in binaries/files of critical packages:\n$out" || pass "rpm -V shows no differences in critical package binaries"
  [ -n "$cfg" ] && warn "CONFIG files differ from the package (check that the changes are yours):\n$cfg"
elif command -v debsums >/dev/null; then
  out=$(debsums -s libc6 coreutils util-linux procps findutils bash openssh-server systemd cron sudo login 2>&1)
  [ -n "$out" ] && fail "debsums reports differences:\n$out" || pass "debsums shows no differences in critical packages"
else warn "neither rpm nor debsums available: package integrity could not be verified"; fi

# --- 9. Network: listening ports -----------------------------------------------------------
echo "INFO  ports listening on all interfaces: $(ss -ltn 2>/dev/null | awk 'NR>1 && $4 ~ /^(0\.0\.0\.0|\*|\[::\])/ {sub(/.*:/,"",$4); print $4}' | sort -un | tr '\n' ' ')"

echo
echo "SUMMARY: FAIL=$FAIL  WARN=$WARN"
[ "$FAIL" = 0 ] && echo "No known indicators. This does NOT prove the absence of compromise (see 'When to reinstall' in the eradication guide)." || echo "Indicators found. Follow the eradication guide."
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
