# Variante de perfctl con `trufflehog` y cuentas de sistema como puerta trasera: análisis de un caso real

**Idioma:** [English](../en/REPORT.md) · Español
**TLP:CLEAR** · Servidor AlmaLinux 8.10 (kernel 4.18) · Compromiso de ~63 horas · Limpieza sin reinstalar

> Este documento está anonimizado: no incluye nombres de organizaciones, hosts, IP de la víctima ni credenciales. Los IOC están en un archivo CSV aparte: [`iocs/perfctl-folddbus-iocs.csv`](../../iocs/perfctl-folddbus-iocs.csv). Para el procedimiento, ve a la [guía de erradicación](GUIA-ERRADICACION.md).

---

## Resumen

Un servidor Linux con Docker presentaba hugepages reservadas sin explicación y una carga inconsistente con la CPU mostrada. La causa era un **minero de Monero con rootkit de la familia perfctl**, instalado como root. Esta variante coincide con lo descrito por [Aqua Nautilus](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/), pero añade elementos que no vimos en reportes públicos: un binario Go residente que se hace pasar por `s6-supervise` dentro del cgroup de `crond`, ejecución de **`trufflehog`**, y **cuentas de sistema (`ftp`, `lp`) con una copia de bash como shell** y llave SSH del atacante.

Se limpió sin reinstalar. No se determinó la vía de entrada.

## Cómo se manifestó

- `vm.nr_hugepages` en 131 (luego 607) pese a existir `/etc/sysctl.d/*` con valor 0. El minero lo ajusta en caliente.
- Carga 10–16 con `top` mostrando 60–90% de CPU libre.
- Herramienta de monitoreo remoto mostrando ~55% de CPU de forma sostenida (cálculo acumulado desde el arranque, que arrastraba el periodo del minero).
- Seis reinicios por kernel crash en dos días (no investigados).

## Coincidencias con perfctl documentado

| Documentado | Observado |
|---|---|
| Disfraz `httpd` | Proceso `httpd -j` |
| `/root/.config/cron/perfcc`, `/usr/bin/perfcc` | Presentes + línea horaria en el crontab de root |
| `/usr/lib/libpprocps.so`, `libfsnkdev.so` | `libpprocps.so` y `libfsnldev.so` (copias del minero, 11 MB) |
| Rootkit `libgcwrap.so` vía `/etc/ld.so.preload` | Presente, con `chattr +i` |
| Falsos `top`, `ldd`, `crontab` en `~/.local/bin`, variable `AAZHDE` | Presentes en `/usr/bin/.local/bin`, variables `HZAA` y `AAZHDE` |
| Directorio `.xdiag` | `/usr/bin/.atmp/tmp/.applocal.xdiag` |

## Novedades de esta variante

1. **Implante residente en Go dentro del cgroup de `crond.service`.** Se llamaba `s6-supervise s6rc-fdholder`, pero su ejecutable real era `/tmp/.perf.c/s6-supervise` (copia del binario de 11 MB). No aparecía en `ps` ni en el listado de `/proc`, pero sí en `/sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs`. Cada 10 s ejecutaba:
   ```
   find /var/spool/cron/crontabs -type f | grep cron | grep '/root$' | xargs cat
   (crontab -l | grep -v -e perfcc -e /tmp/.perf; echo '11 * * * * /root/.config/cron/perfcc') | crontab -
   echo '/etc/coredumps/%e.%p.%u.%t' > /proc/sys/kernel/core_pattern
   ```
2. **Segundo componente disfrazado de `dockerd`**, con ejecutable `/usr/bin/folddbus-send` (permisos 777), lanzado con `nohup folddbus-send <token>` desde `/tmp` y variables `XVEIL=poa`, `APPROC='/usr/bin/dockerd …'`, `AAPCRK`.
3. **`trufflehog`** ejecutado desde `/usr/bin/.atmp/tmp/.applocal.xdiag/` para buscar secretos. El área de staging (`cloud_meta.txt`, `files_other/`, `files_th/`) estaba vacía y la consulta de metadata cloud devolvió un 404.
4. **Puertas traseras con cuentas de sistema:** `ftp` y `lp` con shell `"/sbin/nologin "` (nombre con **espacio al final**) que era una copia de `/usr/bin/bash`, y `authorized_keys` con la misma llave RSA-4096 del atacante. Alias `kbush` y `kkbush` también apuntando a bash.
5. **Docker "oculto":** scripts en `/usr/bin/wbin/` que imitan binarios de Docker/containerd con `env AAZHDE=1`, y un descargador en base64 que usaba un socket `/bin/wbin/run/docker.socket` y `registry.docker.io`. Los falsos `df` y `mount` filtraban cualquier línea con `/wbin/`.
6. **Persistencia en login:** `/root/.bash_profile` con `test -x /bin/perfcc && FPROF=p /bin/perfcc`, y `/etc/profile` con `export PATH=/bin/.local/bin:$PATH`.
7. **Atributos inmutables:** `ld.so.preload`, `libgcwrap.so`, `libfsnldev.so` y `libpprocps.so` con `chattr +i`, y archivos dentro de `.atmp`.

8. **Captura de credenciales y sesiones.** El directorio de trabajo del malware (`/tmp/.xdiag`, ~41 MB) contenía `data/pam/sshd.log` (hook de `pam_authenticate`, coherente con lo descrito para `libgcwrap.so`) y `data/tty/-bash.*.txt` (24 capturas de sesiones bash entre el primer y el último día del compromiso). El archivo de PAM se modificó por última vez durante un login por contraseña hecho el día de la limpieza. **Debe asumirse que las contraseñas usadas en el servidor y lo escrito en sus terminales durante el periodo quedaron expuestas.**
9. **Servicio oculto de Tor y cliente Tor** (`tordata/`, `torrc-*`, archivo `hs.txt` con el identificador del servicio oculto y socket `int/.per.s`), utilizable como canal de acceso y de comunicación. No se observó tráfico a los destinos Tor listados en reportes públicos durante la ventana de observación, pero no se capturó tráfico de red completo.
10. **Proxyjacking:** `/dev/shm/.config/traffmonetizer/cli_device_ids.json`. Coincide con el uso de aplicaciones de monetización de ancho de banda descrito en los reportes.
11. **Seguimiento de PIDs en `/dev/shm/.dmesg/{pds,ino}`**, con un archivo por cada proceso del malware.
12. **Persistencia adicional por `cron.d`:** `/etc/cron.d/perfclean` (`9 * * * * root perfcc`), además de la línea del crontab de root.
13. **Archivo setuid vacío** `apxj` (`-rwsr-sr-t`) y marcadores `/tmp/daisp`, `/tmp/rsr`, `/tmp/go/imports`.

> Nota sobre el directorio de staging: el `.xdiag` de la ruta `/usr/bin/.atmp/tmp/.applocal.xdiag/` guardaba el paquete original del dropper (`trunk.<hash>_<IP>_.sx2.tar.gz`) y un binario `trufflehog` sin modificar.

## Detección que funcionó

- **Contenedor Alpine con el disco del host montado y `--pid=host`.** El rootkit hookea glibc, así que un contenedor basado en musl (por ejemplo `postgres:16-alpine`) veía `ld.so.preload`, la librería y el proceso oculto. Con `--cap-add LINUX_IMMUTABLE` permitió `chattr -i` y borrarlos.
- **Leer `cgroup.procs` en vez de `/proc`.** Comparar el número de PIDs visibles con los de todos los `cgroup.procs` delató procesos ocultos.
- **`auditd` con regla de `execve` sobre `/usr/bin/crontab`** y cadena de padres, que reveló el bucle de reescritura cada 10 s y los comandos del implante.
- **`ldd /usr/bin/ls`** mostró `/lib/libgcwrap.so` cargado aunque `/etc/ld.so.preload` estuviera oculto.
- **`rpm -V`** sobre los paquetes críticos para confirmar que los binarios del sistema estaban intactos, y por tanto que la limpieza sin reinstalar era viable.

## Limpieza (orden que funcionó)

1. Cerrar el acceso (SSH solo por llave, lista de IPs, `AllowUsers root`).
2. Detener `crond` (mata todo su cgroup, incluido el implante oculto) y arrancarlo limpio.
3. Quitar `chattr +i` y borrar `ld.so.preload`, `libgcwrap.so`, las copias del minero y los directorios `.perf.c`, `.atmp`, `wbin`, `.local`.
4. Restaurar crontab, `/etc/profile`, `.bash_profile`, `core_pattern`, `/etc/shells`, `vm.nr_hugepages=0`.
5. Devolver `ftp` y `lp` a `/sbin/nologin` real, bloquearlas y borrar sus `authorized_keys`.
6. Regenerar `ld.so.cache` con `ldconfig`.
7. Reglas de `auditd` sobre `ld.so.preload`, cron, `~/.ssh`, `/etc/passwd`, perfiles y `execve` desde `/tmp`, y monitoreo posterior.

**Verifica después de que el implante esté muerto.** Entre una primera limpieza y la muerte del implante, este recreó `ld.so.preload`, `/etc/profile` (PATH falso), `/root/.bash_profile` (`perfcc`), `/etc/cron.d/perfclean`, `/usr/bin/.local`, `/usr/lib/vei|exi`, la shell falsa de `lp` y su llave SSH. Esos restos solo se encontraron al ejecutar un script de verificación completo horas después. Una comprobación puntual con unos pocos indicadores no los habría detectado.

**Trampa a evitar:** matar los procesos visibles y borrar archivos *sin* detener el implante residente hace que todo se recree en segundos. Hasta no parar el cgroup de `crond`, el rootkit, las librerías y la línea del cron volvieron a aparecer.

## Qué no se sabe

- **La vía de entrada.** Polkit estaba parcheado (CVE-2021-4034) y no había RocketMQ. Había varios servicios expuestos (base de datos y un agente de gestión de Docker con el socket y `/` del host montados) y fuerza bruta SSH constante.
- **Si hubo exfiltración.** `trufflehog` corrió como root durante horas, pero el staging estaba vacío. Además hubo captura local de credenciales y de sesiones de terminal; no se sabe si llegó a enviarse.
- **La causa de los kernel crash.**
- **Garantía de limpieza total.** La recomendación del reporte original, reinstalar, sigue siendo lo más seguro.

## Recomendaciones

- No exponer servicios de administración ni bases de datos a Internet. Un agente que monte `/var/run/docker.sock` y `/` equivale a root remoto.
- SSH solo por llave, con acceso restringido por red y `fail2ban`.
- Montar `/tmp` y `/dev/shm` con `noexec,nosuid`.
- Vigilar `ld.so.preload`, `~/.bash_profile`, `/etc/profile` y el crontab de root con `auditd`.
- Revisar `/etc/passwd` por shells con espacios o fuera de `/etc/shells`, y `authorized_keys` en cuentas de sistema.
- Calcular la CPU como diferencia entre dos lecturas de `/proc/stat`, no con el acumulado.
- Ante una infección confirmada: reconstruir desde una imagen limpia, rotar todos los secretos y revisar el equipo desde el que se administra.

## Guía y herramientas

- [GUIA-ERRADICACION.md](GUIA-ERRADICACION.md): procedimiento detallado, con comandos, verificación y criterios para reinstalar.
- [`verify-perfctl.sh`](../../verify-perfctl.sh): verificación de **solo lectura** de todos los indicadores conocidos (devuelve código 1 si encuentra alguno).
- [`iocs/perfctl-folddbus-iocs.csv`](../../iocs/perfctl-folddbus-iocs.csv): indicadores de compromiso (descripciones en inglés y español).

## Referencias

- [Aqua Security: perfctl, a stealthy malware targeting millions of Linux servers](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)
- [BleepingComputer: Linux malware perfctl behind years-long crypto mining campaign](https://www.bleepingcomputer.com/news/security/linux-malware-perfctl-behind-years-long-crypto-mining-campaign/)
- [Help Net Security: Linux systems targeted with stealthy "Perfctl" cryptomining malware](https://www.helpnetsecurity.com/2024/10/07/perfctl-perfcc-cryptomining-linux/)
- [Security Affairs: New Perfctl malware targets Linux servers](https://securityaffairs.com/169351/malware/perfctl-malware-targets-misconfigured-linux-servers.html)
