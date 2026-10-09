# Variante de perfctl (folddbus-send / tpm_dev_wq / libgcwrap): análisis de un caso, guía de erradicación e IOC

**Idioma:** [English](README.md) · Español

Documento de campo sobre un compromiso real de un servidor Linux con Docker por un **minero de Monero con rootkit de la familia perfctl**, y sobre cómo se eliminó **sin reinstalar**. Describe una variante más reciente que las de los reportes públicos, con comportamientos no descritos en otros lugares:

- un **implante residente en Go oculto dentro del cgroup de `crond.service`**, disfrazado de `s6-supervise`, que reescribe el crontab de root cada 10 segundos y recrea todo lo que borres;
- **captura de credenciales y de sesiones de terminal** (un hook de PAM más grabaciones de sesiones bash) y un **servicio oculto de Tor**;
- `trufflehog` ejecutado como root para buscar secretos, y **proxyjacking** (Traffmonetizer);
- **cuentas de sistema (`ftp`, `lp`) convertidas en puertas traseras SSH**, con una copia de bash como shell (`"/sbin/nologin "`, con espacio al final).

> **El valor de este repositorio está en los documentos detallados**, en especial la [guía de erradicación](docs/es/GUIA-ERRADICACION.md): comandos exactos, el orden que funciona, cómo ver a través del rootkit, cómo verificar y los errores que hicieron fallar limpiezas intermedias.

Se eliminó toda información que identifique a la víctima. **No** se incluyen muestras de malware.

---

## Por dónde empezar

| Si estás... | Ve a |
|---|---|
| **Respondiendo ahora a una infección sospechada** | [Guía de erradicación](docs/es/GUIA-ERRADICACION.md), empezando por las [Reglas de oro](docs/es/GUIA-ERRADICACION.md#1-reglas-de-oro) y la [Vista confiable](docs/es/GUIA-ERRADICACION.md#3-vista-confiable-ver-el-servidor-sin-el-rootkit) |
| **Comprobando si un equipo está afectado** | Ejecuta [`verify-perfctl.sh`](verify-perfctl.sh) (solo lectura) y lee [Confirmar la infección](docs/es/GUIA-ERRADICACION.md#5-confirmar-la-infección) |
| **Construyendo detecciones / cazando amenazas** | [`iocs/perfctl-folddbus-iocs.csv`](iocs/perfctl-folddbus-iocs.csv) y los [Consejos rápidos](#consejos-rápidos-de-detección) |
| **Intentando entender qué pasó** | [Informe del caso](docs/es/INFORME.md) |
| **Decidiendo entre limpiar y reinstalar** | [Cuándo reinstalar (no limpiar)](docs/es/GUIA-ERRADICACION.md#14-cuándo-reinstalar-no-limpiar) |
| **Preocupado por credenciales filtradas** | [Después de limpiar](docs/es/GUIA-ERRADICACION.md#12-después-de-limpiar) |

---

## Qué hay en este repositorio

| Documento | Qué obtienes |
|---|---|
| **[docs/es/GUIA-ERRADICACION.md](docs/es/GUIA-ERRADICACION.md)** · [EN](docs/en/ERADICATION-GUIDE.md) | **La pieza principal.** 15 secciones y 2 apéndices: cómo funciona el malware y por qué importa el orden (§0); reglas de oro; una **"vista confiable" con un contenedor musl** que ve lo que el rootkit oculta ([§3](docs/es/GUIA-ERRADICACION.md#3-vista-confiable-ver-el-servidor-sin-el-rootkit)); preservación de evidencia; contención de acceso; **cómo encontrar y matar al implante oculto a través de los cgroups** ([§7](docs/es/GUIA-ERRADICACION.md#7-neutralizar-el-implante-residente)); eliminación del rootkit y de sus archivos con `chattr +i` ([§8](docs/es/GUIA-ERRADICACION.md#8-eliminar-el-rootkit)); restauración de perfiles, cuentas, llaves y parámetros del kernel; una lista de verificación con resultados esperados ([§11](docs/es/GUIA-ERRADICACION.md#11-verificación)); rotación de credenciales y monitoreo con `auditd` ([§12](docs/es/GUIA-ERRADICACION.md#12-después-de-limpiar)); criterios explícitos para reinstalar ([§14](docs/es/GUIA-ERRADICACION.md#14-cuándo-reinstalar-no-limpiar)); y **10 errores que hicieron fallar intentos intermedios** ([§15](docs/es/GUIA-ERRADICACION.md#15-errores-que-hicieron-fallar-intentos-intermedios)). Incluye equivalencias para Debian/Ubuntu. |
| **[docs/es/INFORME.md](docs/es/INFORME.md)** · [EN](docs/en/REPORT.md) | El análisis del caso: síntomas, tabla de coincidencias con el perfctl documentado, los 13 comportamientos nuevos de esta variante, qué funcionó para detectarlo, el orden de limpieza y lo que sigue sin saberse. |
| **[verify-perfctl.sh](verify-perfctl.sh)** | Un script Bash de **solo lectura** que comprueba ~30 indicadores (rootkit cargado según `ldd`, rutas conocidas, persistencia en cron y perfiles, cuentas y llaves de puerta trasera, hugepages, `core_pattern`, ejecutables sospechosos, procesos **ocultos en `/proc` pero presentes en cgroups**, archivos inmutables, integridad de paquetes, proxyjacking). Código de salida 1 si encuentra algo. La salida del script está en inglés. |
| **[iocs/perfctl-folddbus-iocs.csv](iocs/perfctl-folddbus-iocs.csv)** | Indicadores de compromiso con descripciones en inglés y español: hashes SHA-256, rutas, nombres de procesos, variables de entorno, líneas de persistencia, huella de la llave SSH del atacante y síntomas. |

---

## Hallazgos clave de un vistazo

- **Ventana de compromiso:** unas 63 horas; detectado y limpiado el mismo día. **No se determinó** la vía de entrada (Polkit CVE-2021-4034 estaba parcheado; no había RocketMQ).
- **Por qué `top`/`ps`/`ls` mentían:** `/lib/libgcwrap.so`, cargada mediante `/etc/ld.so.preload`, hookea glibc; falsos `top`/`ldd`/`crontab` ocultaban el resto. El hook además se ocultaba a sí mismo.
- **Por qué borrar archivos no funcionaba:** el implante vivía en el cgroup de `crond.service` y recreaba todo en segundos. **Detén primero ese cgroup.**
- **Qué lo delató:** `ldd /usr/bin/ls` listando el rootkit; hugepages reservadas en caliente; PIDs presentes en `cgroup.procs` pero ausentes de `/proc`; una regla `execve` de `auditd` sobre `crontab`.
- **Evaluación de daños:** el malware capturó datos de autenticación de PAM y sesiones bash durante todo el periodo. **Trata como expuesta cualquier credencial usada en el equipo.**
- **Trampa de la verificación:** una primera limpieza parecía completa, pero el implante recreó `/etc/profile`, `.bash_profile`, `/etc/cron.d/perfclean`, binarios falsos y una segunda cuenta de puerta trasera **antes de que lo mataran**. Solo una verificación completa los encontró horas después.

La línea de tiempo, los comportamientos nuevos y el orden completo de limpieza están en el [informe del caso](docs/es/INFORME.md).

---

## Consejos rápidos de detección

```bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin           # nunca confíes en el PATH heredado
ldd /usr/bin/ls | grep -E "gcwrap|pprocps|fsnldev"   # hook del rootkit cargado, aunque ld.so.preload parezca ausente
awk '/HugePages_Total/{print $2}' /proc/meminfo      # distinto de 0 sin que lo hayas configurado
awk -F: '$7 ~ / $/ {print $1}' /etc/passwd           # shells con espacio al final (cuentas de puerta trasera)
cat /sys/fs/cgroup/systemd/system.slice/crond.service/cgroup.procs   # debería listar solo crond
```

- Compara los PID visibles en `/proc` con todos los `cgroup.procs`: los procesos ocultos solo aparecen en estos últimos ([cómo](docs/es/GUIA-ERRADICACION.md#5-confirmar-la-infección)).
- El rootkit hookea glibc, así que un **contenedor musl** (por ejemplo Alpine) con el disco del host montado y `--pid=host` ve el estado real ([cómo](docs/es/GUIA-ERRADICACION.md#3-vista-confiable-ver-el-servidor-sin-el-rootkit)).
- Detén `crond.service` (mata todo su cgroup, incluido el implante oculto) **antes** de borrar archivos.
- Revisa los `authorized_keys` de las **cuentas de sistema** como `ftp` y `lp`.

## Uso del script de verificación

```bash
sudo bash verify-perfctl.sh
```

Solo lee: no borra, mueve ni cambia nada. Imprime una línea `PASS` / `FAIL` / `WARN` por comprobación y sale con código `1` si encuentra algún indicador, así que puede ejecutarse desde `cron` o un agente de monitoreo. Para mejores resultados ejecútalo dos veces: una en el host y otra desde la [vista confiable](docs/es/GUIA-ERRADICACION.md#3-vista-confiable-ver-el-servidor-sin-el-rootkit). Un resultado limpio **no** prueba la ausencia de compromiso.

## Uso de los IOC

El CSV tiene cuatro columnas: `type`, `value`, `description_en`, `description_es`. Los tipos incluyen `sha256`, `path`, `process`, `env_var`, `persistence`, `command`, `ssh_key_fp`, `ip`, `symptom`, `network` y `campaign_id`. Los marcadores como `<VICTIM_IP>` y `<PID>` representan valores que varían. Las entradas marcadas como SENSIBLE se refieren a archivos con credenciales capturadas: búscalos, nunca los compartas.

## Alcance y límites

- **Sin garantía de eliminación total.** El rootkit manipula `/proc`; la ausencia de pruebas no es prueba de ausencia. [Reinstalar sigue siendo lo más seguro](docs/es/GUIA-ERRADICACION.md#14-cuándo-reinstalar-no-limpiar).
- Los comandos apuntan a **AlmaLinux/RHEL 8** con systemd y cgroups v1; se listan las [equivalencias para Debian/Ubuntu](docs/es/GUIA-ERRADICACION.md#apéndice-a-equivalencias-para-debianubuntu).
- La técnica de la vista confiable requiere un Docker funcional que a su vez no esté comprometido.
- **No se sabe** si hubo exfiltración de datos; la captura local de credenciales está confirmada.
- No se investigaron seis reinicios por kernel crash anteriores al hallazgo.

## Compartir y manipular

Comparte **solo binarios** y el archivo de IOC. No publiques el directorio de trabajo del malware (`.xdiag`, `.atmp`): contiene capturas de terminal y de PAM y datos del servidor. Los archivos `/usr/lib/vei` y `/usr/lib/exi` y el ID de campaña incluyen la IP de la víctima. Ver [Qué guardar para compartir](docs/es/GUIA-ERRADICACION.md#13-qué-guardar-para-compartir-anonimizado).

## Comentarios

¿Viste esta variante, encontraste una carencia o tienes una corrección? Abre un issue o un pull request. Se agradecen especialmente nuevos hashes, rutas o comportamientos.

## Referencias

- [Aqua Nautilus: perfctl, a stealthy malware targeting millions of Linux servers](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)
- [BleepingComputer: Linux malware perfctl behind years-long crypto mining campaign](https://www.bleepingcomputer.com/news/security/linux-malware-perfctl-behind-years-long-crypto-mining-campaign/)
- [Help Net Security](https://www.helpnetsecurity.com/2024/10/07/perfctl-perfcc-cryptomining-linux/) · [Security Affairs](https://securityaffairs.com/169351/malware/perfctl-malware-targets-misconfigured-linux-servers.html)
