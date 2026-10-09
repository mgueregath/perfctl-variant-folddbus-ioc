# Guía de erradicación: perfctl (variante folddbus-send / tpm_dev_wq / libgcwrap) en Linux

Guía paso a paso para limpiar un servidor Linux con Docker infectado por esta variante **sin reinstalar**, basada en una limpieza real. Incluye los comandos exactos, la verificación después de cada fase y los errores que hicieron fallar intentos intermedios.

> **Léela completa antes de ejecutar nada.** Algunos pasos son destructivos o cortan el acceso. Hazlos en el orden indicado.
> **Reinstalar es lo más seguro.** Esta guía es para cuando no se puede, y no garantiza una eliminación total. Ver la sección 14 (cuándo reinstalar).

Los ejemplos usan AlmaLinux/RHEL 8 (`rpm`, `systemd`, cgroups v1). Para Debian/Ubuntu ver el apéndice. Los marcadores `<IP_ADMIN>`, `<RED_ADMIN>` y `<IMAGEN_MUSL>` son valores que debes reemplazar.

---

## 0. Qué hace este malware (para entender el orden)

| Componente | Qué hace | Consecuencia para la limpieza |
|---|---|---|
| **Implante residente** (Go, 3 MB) | Vive dentro del cgroup de `crond.service` con nombre falso (`s6-supervise s6rc-fdholder`). Cada 10 s reescribe el crontab, recrea archivos, cambia `core_pattern`, relanza al minero. | **Mientras esté vivo, todo lo que borres reaparece.** Es lo primero que hay que matar. |
| **Rootkit** `libgcwrap.so` (vía `/etc/ld.so.preload`) | Hookea glibc: oculta procesos y archivos, y **captura credenciales (hook de PAM) y sesiones de terminal**. Se oculta a sí mismo. | Con él activo `ps`, `top`, `ls`, `find` mienten. Hay que usar una *vista confiable* (sección 3). |
| **Minero** (XMRig, 11 MB) | Copias en `/usr/bin/perfcc`, `/root/.config/cron/perfcc`, `/usr/lib/libpprocps.so`, `libfsnldev.so`. Reserva hugepages. | Hay que borrar **todas** las copias. |
| **Falsos `top`, `htop`, `ldd`, `crontab`, `df`, `mount`** | Binarios y scripts en `/usr/bin/.local/bin` que filtran la salida. Se activan con un PATH falso en `/etc/profile`. | Ocultan el minero a quien usa `top`. |
| **Puertas traseras** | Cuentas `ftp` y `lp` con shell `"/sbin/nologin "` (con espacio, copia de bash) y llave SSH del atacante; **servicio oculto de Tor**. | Revisar cuentas y llaves. |
| **Captura de credenciales** | `data/pam/sshd.log` (hook PAM) y `data/tty/*.txt` (sesiones bash) en el directorio de trabajo. | **Hay que asumir que se filtraron las contraseñas escritas en el servidor.** |
| **Proxyjacking** | `traffmonetizer` en `/dev/shm`. | Vende tu ancho de banda. |
| **Persistencia en login** | `/root/.bash_profile` ejecuta `/bin/perfcc`; `/etc/cron.d/perfclean` ejecuta `perfcc` cada hora. | Revisar perfiles y `cron.d`. |

---

## 1. Reglas de oro

1. **No reinicies** hasta terminar. Perderías procesos y estado útil para el análisis, y la persistencia se reactiva al arrancar.
2. **Mantén una segunda sesión SSH abierta** antes de tocar `sshd` o el firewall.
3. **No confíes en las herramientas del servidor** mientras el rootkit esté activo (`ps`, `top`, `ls`, `find`, `lsof`, `ldd`, `crontab -l`).
4. **Mata el implante antes de borrar archivos.**
5. **Mueve a cuarentena en vez de borrar** (`mv`), así puedes revertir.
6. **Verifica varias veces y con tiempo.** El implante recrea archivos hasta el momento de morir: tras matarlo, vuelve a revisar. Una verificación puntual no basta.
7. **Fija el PATH** en cada comando: `export PATH=/usr/sbin:/usr/bin:/sbin:/bin`.
8. **Asume credenciales comprometidas** (sección 12).

---

## 2. Preparación

```bash
# Conecta como root y fija un PATH seguro en TODAS las sesiones
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# Carpeta de trabajo con permisos restringidos
mkdir -p /root/forensics && chmod 700 /root/forensics

# Prueba de que el rootkit está activo: si ldd lista libgcwrap, el hook está cargado aunque ld.so.preload parezca ausente
ldd /usr/bin/ls | head
```

Comprueba qué ve el servidor y qué ve el rootkit (más adelante, en la sección 3). Ten a mano:

- Un **acceso alternativo** al servidor (consola VNC/KVM del proveedor), por si el SSH se corta.
- Una imagen **musl** disponible localmente (por ejemplo `alpine` o `postgres:16-alpine`). Si no hay una, descárgala *antes* de cerrar el egress.

---

## 3. Vista confiable: ver el servidor sin el rootkit

El rootkit usa `LD_PRELOAD`, que solo afecta a programas **glibc**. Un contenedor **musl** (Alpine) con el disco del host montado y el espacio de PIDs del host **no carga el hook** y ve la realidad.

```bash
# Solo lectura
docker run --rm --pid=host --entrypoint sh -v /:/host:ro <IMAGEN_MUSL> -c '
  echo "== preload =="; ls -la --full-time /host/etc/ld.so.preload; cat /host/etc/ld.so.preload
  echo "== libs del malware =="; ls -la /host/lib/libgcwrap.so /host/usr/lib/lib*.so 2>/dev/null
  echo "== buscar por nombre en todo el disco =="
  find /host -xdev \( -name "*gcwrap*" -o -name "perfcc*" -o -name "pctl*" -o -name ".perf*" -o -name "folddbus*" \) 2>/dev/null
  echo "== procesos reales por CPU =="; ps -o pid,ppid,time,vsz,args | sort -k3 -r | head -15
'
```

> Las horas dentro del contenedor salen en **UTC**. Cuenta con la diferencia respecto al reloj del servidor.

**Para modificar** (borrar, `chattr`) usa el mismo comando con `-v /:/host` (sin `:ro`) y `--cap-add LINUX_IMMUTABLE`:

```bash
docker run --rm --pid=host --cap-add LINUX_IMMUTABLE --entrypoint sh -v /:/host <IMAGEN_MUSL> -c '...'
```

> Esto solo funciona si Docker mismo no está comprometido. Si el binario de Docker o el socket estuvieran manipulados, no confíes en este método.

---

## 4. Preservar la evidencia

Antes de borrar, guarda lo necesario (el implante se autodestruye parcialmente y se disfraza):

```bash
Q=/root/forensics; cd $Q

# Binarios y archivos (con permisos restringidos: pueden contener credenciales capturadas)
umask 077
tar czf artefactos.tgz --ignore-failed-read \
  /usr/bin/.local /usr/bin/wbin /usr/bin/.atmp /usr/lib/vei /usr/lib/exi /etc/prdevid \
  "/usr/sbin/nologin " /tmp/.perf.c /tmp/.xdiag /tmp/.t.trf /tmp/k8t /tmp/k8s.run* \
  /dev/shm/.dmesg /dev/shm/.config /etc/cron.d/perfclean /var/spool/cron/root \
  /etc/profile /root/.bash_profile /etc/passwd /etc/shadow /etc/shells /var/ftp/.ssh /var/spool/lpd/.ssh

# Copia de los binarios en memoria (con la vista confiable, si están ocultos)
sha256sum /usr/lib/libpprocps.so /usr/lib/libfsnldev.so /lib/libgcwrap.so /usr/bin/perfcc /usr/bin/folddbus-send 2>/dev/null > hashes.txt
```

**No ejecutes nada de lo que guardes.** Si vas a compartir muestras, comparte **solo los binarios**, no el directorio de trabajo (`.xdiag`, `.atmp`): contiene capturas de terminal y datos del servidor.

---

## 5. Confirmar la infección

Usa el script de este repositorio (solo lectura). Ejecútalo **dos veces**: desde el host y, si es posible, desde la vista confiable.

```bash
bash verify-perfctl.sh
```

Indicadores rápidos manuales (si no puedes usar el script):

```bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
ldd /usr/bin/ls | grep -E "gcwrap|pprocps|fsnldev"             # hook activo
ls /etc/ld.so.preload 2>&1                                       # puede estar oculto
awk '/HugePages_Total/{print $2}' /proc/meminfo                  # != 0 sin que lo hayas configurado
crontab -l | grep -E "perfcc|\.perf"                             # línea del minero
cat /etc/cron.d/* | grep -E "perfcc|perfclean"
grep -n -E "perfcc|/bin/\.local|AAZHDE|HZAA" /etc/profile /root/.bash_profile
awk -F: '$7 ~ / $/ {print $1}' /etc/passwd                       # shells con espacio al final
find / -xdev -name authorized_keys -not -path "/home/*" -not -path "/root/.ssh/*" 2>/dev/null
cat /proc/sys/kernel/core_pattern                                # ¿apunta a /etc/coredumps/?
uptime                                                           # carga alta con CPU "libre" en top
```

**Detección de procesos ocultos** (comparar `/proc` contra los cgroups):

```bash
vis=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
cg=$(cat $(find /sys/fs/cgroup -name cgroup.procs) 2>/dev/null | sort -un)
comm -23 <(echo "$cg") <(echo "$vis")     # PIDs en un cgroup pero ausentes de /proc
# Un par de PIDs efímeros (los de este mismo comando) es normal: repite y fíjate en los que persisten.
```

**El implante oculto se ve en el cgroup de `crond`** (o del servicio donde se haya metido):

```bash
cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs      # debería listar SOLO el PID de crond
for p in $(cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs); do
  echo "$p  exe=$(readlink /proc/$p/exe)"          # el exe de un proceso oculto sí se puede leer
done
```

Si ves un exe en `/tmp`, `/dev/shm` o `/usr/bin/folddbus-send`, ahí está.

---

## 6. Contención de acceso

Hazlo **antes** de limpiar, para que el atacante no reentre.

### 6.1 SSH

```bash
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)

# Solo llaves, solo root (o tu usuario), y solo desde tu IP / red de administración
sed -i -E 's/^#?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q '^AllowUsers' /etc/ssh/sshd_config || echo 'AllowUsers root' >> /etc/ssh/sshd_config   # ajusta al usuario real
cat >> /etc/ssh/sshd_config <<'EOF'

# --- Contención: solo la IP/red de administración ---
Match Address *,!<IP_ADMIN>,!<RED_ADMIN>
    DenyUsers *
EOF
sshd -t && echo "SINTAXIS OK" && systemctl reload sshd
```

> `Match` debe ir **al final** del archivo. Antes de cerrar la sesión actual, **abre otra en paralelo** y comprueba que entras:
> `ssh -o BatchMode=yes -o PreferredAuthentications=publickey usuario@servidor true`
> Y comprueba que una IP no permitida es rechazada: `sshd -T -C addr=8.8.8.8,user=root,host=x,laddr=1.1.1.1,lport=22 | grep -i denyusers`.

### 6.2 Firewall

- Restringe el puerto SSH a la IP/red de administración **en el firewall**, no solo en `sshd`.
- Cierra en el firewall los puertos que no deban ser públicos: bases de datos (5432/3306), paneles de administración (Portainer, 9100 de métricas), puertos de Docker (2375/2376).
- Un agente que monte `/var/run/docker.sock` y `/` del host equivale a **root remoto**: no lo expongas.

---

## 7. Neutralizar el implante residente

**Este es el paso decisivo.** Si borras archivos sin hacerlo, todo vuelve en segundos.

### 7.1 Identificarlo (opcional, para entender)

Con `auditd` puedes ver quién ejecuta `crontab` cada 10 s, con su padre:

```bash
systemctl start auditd
auditctl -D
auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/crontab -F auid=-1 -k cw
sleep 30
# OJO: ausearch sin --input-logs se cuelga esperando stdin si no hay TTY
ausearch --input-logs -k cw -i | grep -a "type=SYSCALL" | head
grep -a 'key="cw"' /var/log/audit/audit.log | grep -o -E " ppid=[0-9]+" | sort -u
```

Si el `ppid` no aparece en `/proc`, está oculto: búscalo en los `cgroup.procs` (sección 5).

### 7.2 Matarlo

Detener el servicio **mata todo su cgroup**, incluidos los procesos que no ves:

```bash
systemctl kill -s SIGKILL crond      # o el servicio donde esté el implante
systemctl stop crond
cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs      # debe quedar vacío
```

> **No arranques `crond` todavía.** Primero limpia los archivos (secciones 8–10), para que el nuevo `crond` no ejecute `perfcc`. Si el implante estuviera en otro cgroup (una sesión de usuario, otro servicio), usa `systemctl kill` sobre ese servicio o `loginctl terminate-session <id>`.

Mata también cualquier proceso restante con ejecutable sospechoso:

```bash
for p in /proc/[0-9]*; do e=$(readlink $p/exe 2>/dev/null); case "$e" in /tmp/*|/dev/shm/*|/var/tmp/*|*deleted*|*folddbus*|*perfcc*|*/.perf.c/*) echo "${p#/proc/} $e";; esac; done
# kill -9 <PID> sobre los que sean del malware (no mates el VS Code Server u otros procesos tuyos)
```

Y los de las sesiones SSH que se infectaron al iniciar sesión (los lanzó `/root/.bash_profile`): en esos casos, cierra las sesiones y vuelve a entrar después de limpiar `.bash_profile`.

---

## 8. Eliminar el rootkit

Con el implante ya muerto:

```bash
docker run --rm --pid=host --cap-add LINUX_IMMUTABLE --entrypoint sh -v /:/host <IMAGEN_MUSL> -c '
  # Quitar el atributo inmutable
  chattr -i /host/etc/ld.so.preload /host/lib/libgcwrap.so /host/usr/lib/libgcwrap.so \
            /host/usr/lib/libpprocps.so /host/usr/lib/libfsnldev.so 2>/dev/null
  # Primero ld.so.preload (así las herramientas del host dejan de cargar el hook)
  rm -f /host/etc/ld.so.preload
  rm -f /host/lib/libgcwrap.so /host/usr/lib/libgcwrap.so /host/lib64/libgcwrap.so
  rm -f /host/usr/lib/libpprocps.so /host/usr/lib/libfsnldev.so /host/usr/lib/libfsnkdev.so
  # Atributos inmutables en rutas críticas (si quedó alguno)
  for d in /host/etc /host/usr/bin /host/usr/sbin /host/usr/lib /host/usr/lib64 /host/root /host/tmp /host/var/spool; do
    lsattr -R $d 2>/dev/null | grep -E "^[-a-zA-Z]{4}i"
  done
'
ldconfig                                    # regenera ld.so.cache (la caché también referenciaba las libs)
ldd /usr/bin/ls | grep -E "gcwrap|pprocps|fsnldev" || echo "hook descargado"
```

---

## 9. Eliminar archivos del malware

Mueve a cuarentena. Comprueba con la vista confiable si el rootkit sigue activo; si ya lo quitaste, las herramientas normales ven bien.

```bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
Q=/root/forensics/quarantine; mkdir -p $Q; chmod 700 $Q

# Quitar inmutables de lo que sigue
chattr -R -i /usr/bin/.local /usr/bin/.atmp /tmp/.perf.c /tmp/.xdiag /dev/shm/.dmesg /dev/shm/.config \
             /etc/cron.d/perfclean "/usr/sbin/nologin " 2>/dev/null

# Binarios del minero y del implante
mv /usr/bin/perfcc /usr/bin/folddbus-send /usr/bin/kbush /usr/bin/kkbush $Q/ 2>/dev/null
mv /root/.config/cron $Q/root_config_cron 2>/dev/null

# Directorios de trabajo
mv /tmp/.perf.c /tmp/.xdiag /tmp/.t.trf /tmp/k8t /tmp/k8s.run* /tmp/daisp /tmp/rsr /tmp/go $Q/ 2>/dev/null
mv /usr/bin/.atmp /usr/bin/.local /usr/bin/wbin $Q/ 2>/dev/null           # /bin es un enlace a /usr/bin
mv /dev/shm/.dmesg /dev/shm/.config $Q/ 2>/dev/null                       # tmpfs: se vacía al reiniciar, pero límpialo ya

# Archivos de identificación
mv /usr/lib/vei /usr/lib/exi /etc/prdevid $Q/ 2>/dev/null

# Persistencia por cron
mv /etc/cron.d/perfclean $Q/ 2>/dev/null
crontab -l | grep -v -E "perfcc|/tmp/\.perf" | crontab -               # revisa que queden solo TUS tareas
crontab -l

# La shell falsa (copia de bash con espacio al final)
mv "/usr/sbin/nologin " $Q/nologin_trojan 2>/dev/null
```

> Antes del `crontab -l | … | crontab -` guarda el crontab: `crontab -l > $Q/crontab.orig`.
> Los falsos `top/htop/ldd/crontab/df/mount` están dentro de `/usr/bin/.local`; ya quedaron movidos.

---

## 10. Restaurar la configuración

### 10.1 Perfiles de login

```bash
cp -a /etc/profile $Q/etc_profile.infectado; cp -a /root/.bash_profile $Q/bash_profile.infectado

sed -i '\|^export PATH=/bin/.local/bin:$PATH$|d' /etc/profile      # PATH falso
sed -i '/perfcc/d' /root/.bash_profile                              # lanzador del malware
grep -n -E "perfcc|/bin/\.local|wbin|AAZHDE|HZAA" /etc/profile /root/.bash_profile /root/.bashrc /etc/bashrc /etc/profile.d/* || echo "perfiles limpios"

# Compara /etc/profile contra el paquete original
rpm -V setup          # solo debería diferir la fecha (T). Si difiere el contenido, revisa a mano.
bash -lc 'echo $PATH'  # NO debe empezar por /bin/.local/bin
```

### 10.2 Cuentas, shells y llaves

```bash
# Shells válidas del sistema
printf "/bin/sh\n/bin/bash\n/usr/bin/sh\n/usr/bin/bash\n/sbin/nologin\n/usr/sbin/nologin\n" > /etc/shells

# Cuentas de sistema usadas como puerta trasera
for u in ftp lp; do usermod -s /sbin/nologin $u; passwd -l $u; done
awk -F: '$7 ~ / $/ {print "MALA:", $1}' /etc/passwd        # no debe imprimir nada
awk -F: '$3==0 {print $1}' /etc/passwd                      # solo root

# Llaves de cuentas de sistema
mv /var/ftp/.ssh /var/spool/lpd/.ssh $Q/ 2>/dev/null
find / -xdev -name authorized_keys -not -path "/proc/*" -not -path "*/forensics*" 2>/dev/null

# Llaves de root: deja SOLO las tuyas
ssh-keygen -lf /root/.ssh/authorized_keys     # reconoce cada una; borra las que no sean tuyas
```

> La huella de la llave RSA-4096 del atacante es `SHA256:kKI/tpGGK0vklmw0DCIzTYVlbklDBvCMXGQsb/nShq8`.

### 10.3 Kernel y recursos

```bash
sysctl -w vm.nr_hugepages=0
sysctl -w kernel.core_pattern='|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e'   # valor por defecto de RHEL 8
cat /proc/sys/kernel/core_pattern
```

### 10.4 Servicios

```bash
systemctl start crond && systemctl is-active crond
cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs | wc -l     # debe ser 1
```

---

## 11. Verificación

Ejecuta el script y comprueba manualmente. **Repite en 5 minutos, 1 hora y 24 horas.**

```bash
bash verify-perfctl.sh           # esperado: FAIL=0
```

Esperado, uno por uno:

| Comprobación | Resultado esperado |
|---|---|
| `ls /etc/ld.so.preload` | No existe |
| `ldd /usr/bin/ls` | Sin `gcwrap` / `pprocps` / `fsnldev` |
| `crontab -l`, `ls /etc/cron.d` | Solo tus tareas; sin `perfcc` ni `perfclean` |
| `grep perfcc /etc/profile /root/.bash_profile` | Sin coincidencias |
| `awk '/HugePages_Total/{print $2}' /proc/meminfo` | 0 |
| `cat /proc/sys/kernel/core_pattern` | No apunta a `/etc/coredumps/` |
| `cat …/crond.service/cgroup.procs \| wc -l` | 1 |
| PIDs en cgroups pero no en `/proc` | Ninguno que persista |
| Procesos con exe en `/tmp`, `/dev/shm`, `deleted` | Ninguno |
| `authorized_keys` en cuentas de sistema | Ninguno |
| `rpm -V` (paquetes críticos) | Sin diferencias en binarios |
| `ls /usr/bin/.local /usr/bin/wbin /usr/bin/.atmp /tmp/.perf.c /tmp/.xdiag /dev/shm/.dmesg` | No existen |
| Carga (`uptime`) y CPU real (diferencia de `/proc/stat`) | Normal |

**Mide la CPU como diferencia**, no como acumulado: el porcentaje "desde el arranque" que muestran algunos paneles sigue alto durante horas tras una limpieza.

```bash
a=($(head -1 /proc/stat)); sleep 5; b=($(head -1 /proc/stat)); ta=0; tb=0
for i in 1 2 3 4 5 6 7; do ta=$((ta+${a[$i]})); tb=$((tb+${b[$i]})); done
awk -v ia=${a[4]} -v ib=${b[4]} -v ta=$ta -v tb=$tb 'BEGIN{printf "%.1f%%\n",(1-(ib-ia)/(tb-ta))*100}'
```

**Si algo reaparece, hay un implante que sigue vivo**: vuelve a la sección 7 y busca en los `cgroup.procs` de todos los servicios y sesiones.

---

## 12. Después de limpiar

### 12.1 Asumir credenciales comprometidas

Este malware **captura credenciales** (hook de PAM → `data/pam/sshd.log`) y **sesiones de terminal** (`data/tty/*.txt`) durante todo el periodo de la infección. Rota **todo lo que se haya usado o esté almacenado en el servidor**:

- Contraseña de root y de cualquier usuario que haya iniciado sesión (por SSH o consola) durante el compromiso.
- Llaves SSH del servidor (las privadas guardadas en él) y las que tengan acceso a otros sistemas.
- Credenciales de bases de datos, de Docker/registries y de paneles (Portainer, etc.).
- Archivos `.env`, secretos de aplicaciones, tokens de API y claves en variables de entorno de los contenedores.
- Si reutilizas contraseñas en otros servicios, cámbialas también.

### 12.2 Endurecimiento mínimo

- SSH solo por llave y restringido por red (sección 6). Instala `fail2ban` o equivalente.
- Cierra puertos no necesarios en el firewall (sección 6.2).
- Monta `/tmp`, `/var/tmp` y `/dev/shm` con `noexec,nosuid,nodev`.
- Aplica las actualizaciones de seguridad (`dnf update --security`).
- No montes `docker.sock` ni `/` del host en contenedores salvo imprescindible.

### 12.3 Monitoreo continuo

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
# Para que persistan tras reiniciar, ponlas en /etc/audit/rules.d/*.rules y ejecuta augenrules --load
```

Y programa el script de verificación (solo lectura) cada hora con un `cron` que **envíe alerta** si devuelve código distinto de 0.

### 12.4 Reiniciar

Cuando todo esté limpio y la evidencia guardada, **reinicia** una vez, en una ventana tranquila, y ejecuta de nuevo el script. Si algo reaparece al arrancar, hay persistencia que no encontraste (unidad systemd, `initrd`, módulo, timer). En ese caso: reinstalar.

---

## 13. Qué guardar para compartir (anonimizado)

- Comparte **solo binarios** (minero, implante, rootkit, falsos `top`/`ldd`), nunca el directorio de trabajo.
- En informes, sustituye IPs, nombres de host, dominios, nombres de contenedores/proyectos y cualquier credencial.
- Los archivos `vei`, `exi` y el ID de campaña (`poa_<IP>`) contienen la IP de la víctima.
- Los capturas de `data/tty` y `data/pam` son **datos sensibles**: no los subas ni los pegues en tickets.

---

## 14. Cuándo reinstalar (no limpiar)

Reinstala desde una imagen limpia si ocurre **cualquiera** de estos puntos:

- `rpm -V` (o `debsums`) muestra diferencias en **binarios** de paquetes críticos (glibc, coreutils, openssh, systemd, bash, sudo, shadow-utils).
- Hay **módulos de kernel** desconocidos (`lsmod`), `tainted != 0` sin explicación, o programas eBPF que no reconoces.
- Algo **reaparece tras reiniciar** y no encuentras de dónde sale.
- No puedes identificar la vía de entrada y el servidor guarda secretos de alto valor.
- El implante estuvo **semanas** (esta variante estuvo ~63 horas), o hay indicios de movimiento lateral hacia otros equipos.
- No tienes la certeza de haber hallado todo: el rootkit manipula `/proc`, así que la ausencia de pruebas no es prueba de ausencia.

Si reinstalas: restaura **solo datos** (volcados de bases de datos, volúmenes), no binarios ni configuración; rota todos los secretos; y revisa los equipos desde los que administrabas el servidor.

---

## 15. Errores que hicieron fallar intentos intermedios

1. **Borrar sin matar el implante.** Todo reaparecía en segundos. El implante vivía en el cgroup de `crond`.
2. **Fiarse de `ps`/`top`/`ls`.** Con `libgcwrap` cargado no mostraban el minero ni los archivos.
3. **`rm` sin `chattr -i`.** Daba "Operation not permitted" en `ld.so.preload` y las librerías.
4. **Olvidar `ldconfig`.** `ld.so.cache` seguía listando las librerías del malware.
5. **No verificar de nuevo tras matar al implante.** Entre mi primera "limpieza" y la muerte del implante pasaron más de 20 minutos, y el implante recreó `ld.so.preload`, `/etc/profile`, `/root/.bash_profile`, `/etc/cron.d/perfclean`, `.local`, `vei`, `exi`, `nologin ` y llaves en `lp`. Una revisión posterior encontró los restos. **Verifica siempre después de que el implante esté muerto.**
6. **`ausearch` sin `--input-logs`** se cuelga esperando stdin y acumula procesos.
7. **Un muestreador `ps | grep crontab` se detecta a sí mismo**: guarda el script en un archivo y usa `pgrep -x`.
8. **Buscar solo por nombre.** El implante se llamaba `s6-supervise` y `dockerd`. Comparar `exe` (`readlink /proc/PID/exe`) con el nombre declarado delató el disfraz.
9. **Confiar en un indicador de CPU acumulado** (calculado desde el arranque) para decidir si el minero seguía activo.
10. **Bloquear tu propia IP.** Si restringes SSH por IP y tu IP es dinámica, te quedas fuera. Ten una vía alternativa (VPN/ZeroTier) o una consola del proveedor.

---

## Apéndice A: equivalencias para Debian/Ubuntu

| RHEL/AlmaLinux | Debian/Ubuntu |
|---|---|
| `rpm -V paquete` | `debsums -s paquete` (instalar `debsums`) o `dpkg -V paquete` |
| `rpm -qf archivo` | `dpkg -S archivo` |
| Servicio `crond` | Servicio `cron` (`systemctl kill -s SIGKILL cron`) |
| `dnf update --security` | `unattended-upgrade` / `apt upgrade` |
| `/etc/sysconfig/...` | `/etc/default/...` |
| `core_pattern` por defecto | `|/usr/share/apport/apport ...` (Ubuntu) o `core` |
| `/usr/lib/systemd/system` | `/lib/systemd/system` |

## Apéndice B: referencias

- [Aqua Nautilus: perfctl](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/linux-malware-perfctl-behind-years-long-crypto-mining-campaign/)
- [Help Net Security](https://www.helpnetsecurity.com/2024/10/07/perfctl-perfcc-cryptomining-linux/)
- [Security Affairs](https://securityaffairs.com/169351/malware/perfctl-malware-targets-misconfigured-linux-servers.html)
