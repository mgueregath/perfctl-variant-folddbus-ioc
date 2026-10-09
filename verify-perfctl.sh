#!/bin/bash
# verify-perfctl.sh - Verificacion de SOLO LECTURA de indicadores de la variante perfctl
# (folddbus-send / tpm_dev_wq / libgcwrap). No modifica ni borra nada.
#
# Uso (como root):   bash verify-perfctl.sh
# Ideal: ejecutarlo tambien desde un contenedor musl con el host montado (ver GUIA-ERRADICACION.md,
# seccion "Vista confiable"), porque el rootkit puede mentirle a las herramientas del host.
#
# Salida: una linea PASS/FAIL/WARN por comprobacion y un resumen. Codigo de salida: 0 si no hay FAIL.

export PATH=/usr/sbin:/usr/bin:/sbin:/bin   # evita PATHs envenenados (p. ej. /bin/.local/bin)
FAIL=0; WARN=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %b\n' "$1"; FAIL=$((FAIL+1)); }
warn() { printf 'WARN  %b\n' "$1"; WARN=$((WARN+1)); }

[ "$(id -u)" = 0 ] || { echo "Ejecuta como root."; exit 2; }

# --- 1. Rootkit LD_PRELOAD -------------------------------------------------------------------
if [ -e /etc/ld.so.preload ]; then fail "/etc/ld.so.preload existe: $(cat /etc/ld.so.preload 2>/dev/null)"; else pass "/etc/ld.so.preload no existe"; fi
if ldd /usr/bin/ls 2>/dev/null | grep -q -E "gcwrap|libpprocps|libfsnldev"; then
  fail "ldd /usr/bin/ls carga una libreria del malware (el hook esta activo aunque ld.so.preload parezca ausente)"
else pass "ldd /usr/bin/ls sin librerias del malware"; fi
for f in /lib/libgcwrap.so /usr/lib/libgcwrap.so /lib64/libgcwrap.so /usr/lib/libpprocps.so /usr/lib/libfsnldev.so /usr/lib/libfsnkdev.so; do
  [ -e "$f" ] && fail "existe $f"
done
ldconfig -p 2>/dev/null | grep -q -E "gcwrap|pprocps|fsnldev|fsnkdev" && fail "ld.so.cache referencia librerias del malware (ejecuta ldconfig tras borrarlas)"

# --- 2. Archivos y directorios conocidos ------------------------------------------------------
for p in /usr/bin/perfcc /bin/perfcc /root/.config/cron/perfcc /usr/bin/folddbus-send /tmp/.perf.c /tmp/.t.trf /tmp/k8t \
         /usr/bin/.atmp /usr/bin/.local /bin/.local /usr/bin/wbin /usr/bin/kbush /usr/bin/kkbush /usr/lib/vei /usr/lib/exi /etc/prdevid \
         /etc/cron.d/perfclean /dev/shm/.dmesg /dev/shm/.config/traffmonetizer /tmp/daisp /tmp/rsr /tmp/go/imports /tmp/.xdiag; do
  [ -e "$p" ] && fail "existe $p"
done
ls /tmp/k8s.run* >/dev/null 2>&1 && fail "existen marcadores /tmp/k8s.run*"
[ -e "/usr/sbin/nologin " ] && fail "existe '/usr/sbin/nologin ' (con espacio): shell de puerta trasera"
pass "(fin de la busqueda de rutas conocidas)"

# --- 3. Persistencia: cron y perfiles ----------------------------------------------------------
if crontab -l 2>/dev/null | grep -q -E "perfcc|/tmp/\.perf|\.config/cron"; then fail "crontab de root contiene perfcc"; else pass "crontab de root sin perfcc"; fi
grep -l -r -s -E "perfcc|perfclean|\.perf\.c" /var/spool/cron /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/crontab 2>/dev/null | grep -q . \
  && fail "perfcc referenciado en cron del sistema"
for f in /etc/profile /etc/bashrc /etc/bash.bashrc /root/.bash_profile /root/.bashrc /root/.profile /etc/profile.d/*; do
  [ -f "$f" ] && grep -q -E "perfcc|/bin/\.local|wbin|AAZHDE|HZAA" "$f" 2>/dev/null && fail "perfil contaminado: $f"
done
pass "(fin de la revision de perfiles)"
for u in /etc/systemd/system /usr/lib/systemd/system /run/systemd/system; do
  grep -l -r -s -E "perfcc|folddbus|\.perf\.c|libgcwrap" "$u" 2>/dev/null | grep -q . && fail "unidad systemd referencia al malware en $u"
done

# --- 4. Cuentas y llaves SSH -----------------------------------------------------------------
badshell=$(awk -F: '$7 ~ / $/ {print $1}' /etc/passwd)
[ -n "$badshell" ] && fail "cuentas con shell que termina en espacio: $badshell" || pass "ninguna shell con espacio al final"
notin=$(awk -F: '$7!="" {print $7}' /etc/passwd | sort -u | grep -v -E '^/(bin|sbin)/(sync|halt|shutdown)$' | while read -r s; do grep -qxF "$s" /etc/shells || echo "[$s]"; done | tr '\n' ' ')
[ -n "$notin" ] && warn "shells en /etc/passwd que no estan en /etc/shells: $notin"
sys_keys=$(find / -xdev -name authorized_keys -not -path "/proc/*" -not -path "/root/.ssh/*" -not -path "/home/*" -not -path "*/forensics*" -not -path "*/quarantine*" 2>/dev/null)
[ -n "$sys_keys" ] && fail "authorized_keys fuera de root y /home (cuentas de sistema): $sys_keys" || pass "sin authorized_keys en cuentas de sistema"
if find / -xdev -name authorized_keys* -not -path "/proc/*" -not -path "*/forensics*" -not -path "*/quarantine*" 2>/dev/null | xargs -r -n1 ssh-keygen -lf 2>/dev/null | grep -q "kKI/tpGGK0vklmw0DCIzTYVlbklDBvCMXGQsb/nShq8"; then
  fail "llave SSH del atacante presente (SHA256:kKI/tpGGK0vklmw0DCIzTYVlbklDBvCMXGQsb/nShq8)"; else pass "llave del atacante no encontrada"; fi
for f in /root/.ssh/authorized_keys; do [ -f "$f" ] && echo "INFO  llaves autorizadas de root: $(grep -c -E '^(ssh|ecdsa|sk-)' "$f")  (confirma que TODAS son tuyas)"; done
awk -F: '$3==0 {print $1}' /etc/passwd | grep -vx root | grep -q . && fail "hay otras cuentas con UID 0"

# --- 5. Efectos en el kernel / sysctl ---------------------------------------------------------
hp=$(awk '/HugePages_Total/ {print $2}' /proc/meminfo)
[ "${hp:-0}" != 0 ] && fail "HugePages_Total=$hp (el minero reserva hugepages; si no las configuraste tu, es indicador)" || pass "HugePages_Total=0"
cp=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
case "$cp" in /etc/coredumps/*) fail "core_pattern alterado: $cp";; *) pass "core_pattern normal: $cp";; esac
[ "$(cat /proc/sys/kernel/tainted 2>/dev/null)" != 0 ] && warn "kernel tainted=$(cat /proc/sys/kernel/tainted) (revisa lsmod)"

# --- 6. Procesos: ejecutables sospechosos y ocultos ---------------------------------------------
sus=""
for p in /proc/[0-9]*; do
  pid=${p#/proc/}; e=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$e" in /tmp/*|/dev/shm/*|/var/tmp/*|*"(deleted)"*|*folddbus*|*perfcc*|*/.perf.c/*|/usr/bin/.*) sus="$sus\n  pid=$pid exe=$e";; /root/.vscode-server/*) ;; /root/.*) sus="$sus\n  pid=$pid exe=$e";; esac
done
[ -n "$sus" ] && fail "procesos con ejecutable sospechoso:$(printf '%b' "$sus")" || pass "ningun proceso ejecuta desde /tmp, /dev/shm, rutas ocultas o borrado"

for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -q -E '^(XVEIL|AAPCRK|APPROC|AAZHDE|HZAA)=' && fail "proceso $pid con variables de entorno del malware ($(readlink "$p/exe" 2>/dev/null))"
done

ps -eo args 2>/dev/null | grep -i -E "traffmonetizer|bitping|repocket|earnfm|earn\.fm|speedshare|honeygain|packetstream|peer2profit" | grep -v grep | grep -q . \
  && fail "proceso de proxyjacking en ejecucion (traffmonetizer/bitping/repocket/etc.)" || pass "sin procesos de proxyjacking conocidos"

# PIDs que existen en algun cgroup pero no aparecen en el listado de /proc (procesos ocultos).
# Se re-verifica tras 1 s para descartar procesos efimeros (incluidos los de este propio script).
cg=$(cat $(find /sys/fs/cgroup -name cgroup.procs 2>/dev/null) 2>/dev/null | sort -un)
vis=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
cand=$(comm -23 <(echo "$cg") <(echo "$vis"))
sleep 1
hidden=""
for pid in $cand; do
  [ -e /sys/fs/cgroup/systemd ] || true
  if kill -0 "$pid" 2>/dev/null && ! ls /proc | grep -qx "$pid"; then hidden="$hidden $pid"; fi
done
[ -n "$hidden" ] && fail "procesos que viven en cgroups pero estan ocultos en /proc:$hidden" || pass "ningun proceso oculto persistente (cgroup.procs vs /proc)"

n=$(cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs 2>/dev/null | wc -l)
[ "$n" -gt 1 ] 2>/dev/null && fail "crond.service tiene $n procesos en su cgroup (deberia ser 1; ahi se escondia el implante)" || pass "cgroup de crond.service con 1 proceso"
[ -d /sys/fs/cgroup/systemd/system.slice/cron.service ] && {
  n=$(cat /sys/fs/cgroup/systemd/system.slice/cron.service/cgroup.procs | wc -l); [ "$n" -gt 1 ] && warn "cron.service tiene $n procesos (Debian/Ubuntu: revisa)"; }

# --- 7. Atributos inmutables en rutas de sistema -----------------------------------------------
imm=$(lsattr -R /etc /usr/lib /usr/lib64 /usr/bin /usr/sbin /lib /lib64 /root /tmp /var/spool /var/ftp 2>/dev/null | grep -E '^[-a-zA-Z]{4}i' | head -20)
[ -n "$imm" ] && fail "archivos inmutables (chattr +i) en rutas de sistema:\n$imm" || pass "sin archivos inmutables en rutas de sistema"

# --- 8. Integridad de paquetes -----------------------------------------------------------------
if command -v rpm >/dev/null; then
  all=$(rpm -V --nomtime glibc coreutils util-linux procps-ng findutils bash openssh openssh-server systemd cronie sudo shadow-utils audit setup 2>&1)
  out=$(echo "$all" | grep -v -E '^\S+\s+c /' )
  cfg=$(echo "$all" | grep -E '^\S+\s+c /' )
  [ -n "$out" ] && fail "rpm -V reporta diferencias en binarios/archivos de paquetes criticos:\n$out" || pass "rpm -V sin diferencias en binarios de paquetes criticos"
  [ -n "$cfg" ] && warn "archivos de CONFIGURACION distintos del paquete (revisa que los cambios sean tuyos):\n$cfg"
elif command -v debsums >/dev/null; then
  out=$(debsums -s libc6 coreutils util-linux procps findutils bash openssh-server systemd cron sudo login 2>&1)
  [ -n "$out" ] && fail "debsums reporta diferencias:\n$out" || pass "debsums sin diferencias en paquetes criticos"
else warn "ni rpm ni debsums disponibles: no se pudo verificar la integridad de paquetes"; fi

# --- 9. Red: puertos y conexiones --------------------------------------------------------------
echo "INFO  puertos escuchando en todas las interfaces: $(ss -ltn 2>/dev/null | awk 'NR>1 && $4 ~ /^(0\.0\.0\.0|\*|\[::\])/ {sub(/.*:/,"",$4); print $4}' | sort -un | tr '\n' ' ')"

echo
echo "RESUMEN: FAIL=$FAIL  WARN=$WARN"
[ "$FAIL" = 0 ] && echo "Sin indicadores conocidos. Esto NO prueba ausencia total de compromiso (ver GUIA-ERRADICACION.md, seccion 'Cuando reinstalar')." || echo "Hay indicadores. Sigue la guia de erradicacion."
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
