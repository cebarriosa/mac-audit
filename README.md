# mac-audit

A single script that checks the health and security of a Mac you don't fully trust, for example after a phishing attack. It reports:

- disk space and what is using it
- user accounts and anything unusual about them
- caches that are safe to delete, and how much space that frees
- security settings (SIP, Gatekeeper, FileVault, firewall, updates, remote access)
- **signs of compromise**: things that start automatically, login items, device management profiles, extra trusted certificates, proxies, DNS changes, browser extensions, unsigned programs
- **what was downloaded and opened**, with anything opened from Mail flagged
- network interfaces, open connections, and **how many other devices are on the local network**

It only uses tools that ship with macOS (`/bin/bash` 3.2, `codesign`, `dscl`, `sqlite3`, `lsof`…). It does **not** need Homebrew, Python or anything else installed, so it runs on a fresh Mac or one in an unknown state.

**It is read-only.** Nothing on the Mac changes unless you pass `--clean`.

## Quick start

1. Copy `mac-audit.sh` to the Mac (AirDrop, USB, or `git clone`).
2. Optional but recommended: give Terminal **Full Disk Access**
   (*System Settings › Privacy & Security › Full Disk Access › add Terminal*). Without it, Mail attachments and some Library folders can't be read.
3. Open Terminal in the folder with the script and run:

```bash
sudo bash mac-audit.sh
```

Running it with `bash` avoids the macOS block on files that came from another computer. It works without `sudo` too, but it skips other users, login items, sudo rules and other programs' network connections.

A full run takes about 2–5 minutes. Most of that time goes to measuring folder sizes and checking for updates.

## Options

| Option | What it does |
|---|---|
| `--clean` | After the audit, offers to delete the **SAFE** caches, asking before each one |
| `--days N` | How many days back counts as "recent" for new accounts, downloads, apps and launch items. Default `30` |
| `--no-lan-scan` | Skip discovering devices on the local network (for example on an office network where scanning is not welcome) |
| `--output DIR` | Where to write the report folder. Default: current folder |
| `-h`, `--help` | Show help |

## Output

On screen every check is tagged:

- `[OK]`: nothing wrong
- `[WARN]`: worth a look; often fine, but you should know what it is
- `[ALERT]`: likely a problem, look at it first
- `[SKIP]`: couldn't check (usually needs `sudo` or Full Disk Access)

A summary at the end lists every alert and warning. The script also creates a folder `mac-audit-<computer>-<date>/` containing:

| File | Contents |
|---|---|
| `report.txt` | Everything shown on screen, without colors |
| `downloads-<user>.txt` | Full download history for the period |
| `background-items.txt` | Full list of login and background items (only with `sudo`) |

> **The report folder contains private data**: user names, download history, IP addresses, installed apps. Don't share it publicly. `.gitignore` already excludes it from this repo.

## What it checks

| # | Section | Details |
|---|---|---|
| 1 | System | macOS version, uptime, XProtect version, pending updates, update history |
| 2 | Disk | Usage per volume (warns at 80% full, alerts at 90%), local Time Machine snapshots, largest folders in each home and its `Library` |
| 3 | Caches | Each item marked **SAFE** (can be deleted), **REVIEW** (look first) or **NEVER** (managed by macOS), with sizes and the total `--clean` could free |
| 4 | Users | Extra root (UID 0) accounts, admins, hidden or recently created accounts, Guest, automatic login, recent logins, SSH `authorized_keys`, custom sudo rules |
| 5 | Security settings | SIP, Gatekeeper, FileVault, firewall and stealth mode, automatic updates, password after sleep, remote access (SSH, Screen Sharing, ARD, SMB, AFP, RDP) |
| 6 | Signs of compromise | Launch agents and daemons (signature, script interpreters, temporary or hidden paths, recent changes), login and background items, cron, login hooks, authorization plugins, configuration profiles and MDM, system and kernel extensions, extra trusted root certificates, shell startup files, Chrome/Edge/Brave/Vivaldi/Arc/Firefox/Safari extensions (flags those that can read every website) |
| 7 | Downloads and apps | Download history (anything opened from Mail is flagged), risky files (installers, archives, scripts, HTML/SVG) received recently in Mail attachments, Downloads and Desktop, with where they came from. Executables in temporary or shared folders, unsigned or rejected apps |
| 8 | Running programs | Unsigned programs, programs running from temporary, hidden or mounted-disk locations, and a list of the developers behind everything running |
| 9 | Network | Interfaces and VPN tunnels, router, DNS servers (flags unknown ones set by hand), proxies, `/etc/hosts`, Wi-Fi security, mounted shares, listening programs, open connections by program, **devices on the local network** (ping sweep + ARP + Bonjour names) |

## Cleanup (`--clean`)

```bash
sudo bash mac-audit.sh --clean
```

- Runs only **after** the full audit.
- Warns that deleting caches also deletes evidence of what happened. If the audit found alerts, it tells you to review them first.
- You must type `YES` to start, then confirm every folder (`y/N`).
- Only deletes the **contents** of SAFE folders inside users' home folders:
  - `~/Library/Caches`
  - Xcode DerivedData and DeviceSupport
  - simulator caches
  - npm, Gradle and Maven caches
  - `~/.cache`
- **Never** touches Downloads, Trash, logs, Mail attachments, backups or anything outside the home folders.

Quit your browsers and other apps before cleaning.

## Limitations

- **A clean report doesn't prove the Mac is clean.** It means none of the known signs this script looks for were found.
- **The device count can be too low.** Sleeping devices and devices with a strict firewall may not answer. On networks larger than `/22`, only the 254 addresses around this Mac are scanned.
- **Download URLs may be missing.** Recent macOS versions no longer store the URL in the download history. For risky files the script reads the source from the file's own metadata instead.
- **The Wi-Fi network name may show as `<redacted>`.** macOS hides it from apps without Location access.
- **Developer machines produce some expected warnings**, for example tools in hidden folders like `~/.npm` or `~/.cache`.

## After a phishing email

1. **If a password was typed on a page from the email:** change it now from **another device**, turn on 2FA, and sign out all other sessions.
2. **Check that email account** for forwarding rules, filters, app passwords and connected apps you didn't create. Attackers add these to keep reading mail.
3. **If a file from the email was opened** (see "Opened from Mail" and "Mail attachment" in the report), the safest fix is to back up documents (not apps) and erase and reinstall macOS.

## Requirements

- Tested on macOS 27 with the stock `/bin/bash` 3.2. Commands missing on older versions are skipped or replaced automatically: login items need macOS 13+, and the `xprotect` and `kmutil` commands are swapped for older equivalents.
- An admin account for `sudo`.
- Internet only for the software update check (it gives up after 90 seconds).
