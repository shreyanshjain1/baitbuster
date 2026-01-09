# BaitBuster 🛡️

**Background phishing + malicious-domain protection** with DNS filtering, URL scoring, temporary allows, policy sync, reporting, and a lightweight download/attachment shield.

> This is a defensive/educational tool meant to reduce risk from suspicious links and unsafe downloads. It is **not** a replacement for enterprise endpoint protection.

---

## Highlights

- **DNS background protection** (blocks phishing/malicious domains + ads/trackers) for browsers/apps
- **Suspicious Link Scanner** with explainable reasons + score
- **Safe Mode** (one-click stricter defaults)
- **Temporary allow rules** (auto-expiring)
- **Policy sync** via hosted `policy.json` (useful for teams)
- **Reports & logs** (CSV/PDF export depending on build)
- **Download Shield** (monitors Downloads folder; optional quarantine; optional Windows Defender scan)

---

## Requirements

- Windows 10/11
- Python 3.11+ (recommended: 3.12)
- Admin privileges **only if** using DNS binding on port 53 and system DNS switching

---

## Install & Run (PowerShell)

From the project folder:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python .\baitbuster_desktop_pro_plus.py
```

### Running with DNS filtering on port 53
Open **PowerShell as Administrator** and run the same commands.

---

## Team Policy Sync

You can host a shared policy file (example in `policy.json`) and point BaitBuster to it.

### Example `policy.json`
```json
{
  "safe_mode": true,
  "block_shorten": true,
  "new_domain_threshold": 30,
  "new_domain_window_sec": 60,
  "blocklist": ["example-phish.com"],
  "allowlist": ["google.com", "microsoft.com"]
}
```

---

## Remote Blocklist

Host a plain text list (example in `remote_blocklist.txt`), one domain per line.

---

## Disclaimer

This project is provided “as-is” with no warranty. Use at your own risk.  
Do not use it to spy on users or bypass security controls.
