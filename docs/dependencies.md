# Dependency audit

Runtime and tests use only the Python 3.12+ standard library. No external Python packages, vendored code, drivers, binaries or recursively installed skills are required. Tkinter ships with the Windows python.org installer; some Linux distributions package Tk separately. This repository does not install it automatically.

OS commands are optional adapters: Windows netsh/PowerShell and Linux ip/NetworkManager nmcli. Missing commands are reported as evidence gaps. They are supplied by the operating system and never downloaded by this tool.

Official command references reviewed 2026-10-28:

- [Windows netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [Windows Wi-Fi location access](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes)
- [NetworkManager nmcli](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html)

## Reviewed CI action pins

The following official release/commit/license/action metadata was reviewed on 2026-10-28. Full commits are pinned in `.github/workflows/ci.yml`; there are no pip installs, automatic dependency updates or local-report uploads.

| Repository | Release | Full reviewed commit | License | Review date |
| --- | --- | --- | --- | --- |
| [actions/checkout](https://github.com/actions/checkout) | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | MIT | 2026-10-28 |
| [actions/setup-python](https://github.com/actions/setup-python) | v7.1.0 | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` | MIT | 2026-10-28 |

Both use the Node 24 action runtime. The workflow requests read-only `contents`, disables checkout credential persistence, uses no secrets, and runs standard-library offline/loopback tests, compile and synthetic demo generation on Windows/Ubuntu with Python 3.12/3.13. Python runtimes/actions are provided by the hosted runner; no third-party Python runtime/test packages are installed. Workflow configuration is not evidence that hosted CI has already passed.

No source dependency was cloned, installed or vendored for this implementation. OS adapter commands and Python/Tk remain environment-provided optional capabilities, with unavailable evidence reported honestly.

## Optional preinstalled packet capture capability

Built-in live capture uses Python ctypes and optional OS capture access. It does
not download, install, redistribute or vendor Npcap, libpcap, SDK files or drivers.
This is an environment capability, not a newly installed source dependency;
there is no source checkout or reviewed source commit to pin. Npcap distribution
is governed by its [vendor license](https://npcap.com/oem/); this project ships none
of its binaries. Linux libpcap, when available, is supplied by the OS environment.
No Linux library version, package provenance or hash was measured on this Windows
host. AF_PACKET itself is a Linux kernel interface.

Read-only Windows component inspection on 2026-10-28 (not a capture smoke test):

| Property | Observed value |
| --- | --- |
| Installed component | `C:/Windows/System32/Npcap/wpcap.dll` |
| File/Product version | `1.10.7` (DLL component, not verified driver release) |
| File metadata company | The TCPdump Group |
| Authenticode | Valid, Nmap Software LLC signer |
| SHA256 | `332f81cc1671a6d12ab4d20264a00ee16d12f6883745e05c92ee4030b3896a9f` |
| Installation time / source commit | Not measured / not applicable to this installed binary |

The file was already installed; no dependency operation was performed. These local
facts identify this inspected component only and do not establish driver service
readiness, permissions, packet capture success, or redistribution permission.
Windows loading uses only the absolute system Npcap path with restricted
DLL-directory + SYSTEM32 dependency search. API declarations were checked with
Context7's `/the-tcpdump-group/libpcap` and focused official Npcap/libpcap
references, without sending project code or local evidence. See
[live capture](live-capture.md) for capability requirements and verification limits.

The desktop integration adds no package or binary dependencies. PNG/GIF loading
uses the environment's Tk image decoder after bounded local header/frame checks;
SVG output is generated from typed data with no external images/resources.
Catalog files are data, not executable plugins; importing them installs nothing.
Vendor references remain [Npcap](https://npcap.com/guide/),
[Npcap licensing](https://npcap.com/oem/), and
[libpcap](https://www.tcpdump.org/manpages/pcap.3pcap.html) (libpcap uses its
upstream BSD license; any OS-installed package remains supplied by that OS).
No DLL, driver, library version or source commit is invented as a dependency pin.
Python, Tk, optional native capture access and optional collector commands are
environment prerequisites, with unavailable capabilities reported explicitly.
