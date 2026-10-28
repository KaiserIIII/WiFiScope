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
