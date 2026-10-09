# perfctl variant (folddbus-send / tpm_dev_wq): case analysis and IOCs

Analysis of a real-world compromise of a Linux/Docker server by a **perfctl-family Monero miner with rootkit**, including features not seen in the public reports: a resident Go implant hidden inside the `crond.service` cgroup, `trufflehog` execution, and system accounts (`ftp`, `lp`) turned into SSH backdoors with a bash copy as their shell.

All victim-identifying information has been removed.

## Contents

| File | Description |
|---|---|
| [`perfctl-variante-folddbus-informe.md`](perfctl-variante-folddbus-informe.md) | Case write-up (Spanish): symptoms, new behaviors, detection that worked, cleanup order, open questions and recommendations. |
| [`perfctl-variante-folddbus-ioc.csv`](perfctl-variante-folddbus-ioc.csv) | Indicators of compromise: SHA-256 hashes, paths, process names, environment variables, attacker SSH key fingerprint, persistence lines and symptoms. |

## Quick detection tips

- `ldd /usr/bin/ls` listing `/lib/libgcwrap.so` means the rootkit is loaded, even if `/etc/ld.so.preload` looks absent.
- Compare PIDs visible in `/proc` against every `cgroup.procs` under `/sys/fs/cgroup/systemd`; hidden processes show up only in the latter.
- The rootkit hooks glibc: a musl-based container (for example Alpine) with the host disk mounted and `--pid=host` sees the real state.
- Stop `crond.service` (kills its whole cgroup, including the hidden implant) *before* deleting files, or everything is recreated within seconds.
- Check `/etc/passwd` for shells with a trailing space and `authorized_keys` on system accounts such as `ftp` and `lp`.

## Notes

- Initial access vector was not determined. Polkit CVE-2021-4034 was patched.
- Further reading on the original family: [Aqua Nautilus](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/).
- Use the IOCs for detection only. Malware samples are not included in this repository.
