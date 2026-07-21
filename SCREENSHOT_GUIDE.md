# Screenshot Placement Guide

Put your image files in the `screenshots/` folder using the exact filenames below, and they'll render automatically in the README. Each entry tells you **which screenshot you already have** maps to which finding.

| Filename to save as | Finding | Which of your screenshots to use |
|---|---|---|
| `screenshots/01-external-rdp-sources.png` | Finding 1 — External RDP | The `RemoteInteractive` summary showing `RemoteIP` + `RemoteIPType` with `136.144.33.18` / `193.36.225.245` marked **Public** (and `10.0.8.8` Private). *(Your Q03 result screenshot — the one with Private/Public labels and session counts.)* |
| `screenshots/03-recon-burst.png` | Finding 3 — Recon | The process-list screenshot showing the ordered burst: `whoami` → `hostname` → `net use` → `net view` → `net view \\NH-FS-01`, plus the second cluster with `net view /domain:nimbus` and the `nslookup` sweep. *(Your Q05 screenshot.)* |
| `screenshots/04-red-herring.png` | Finding 4 — IT box red herring | The `nh-wks-it-01` process activity showing rows launched by `system` / `network service` (the first-logon / RDP-setup noise). *(One of your Q15 screenshots — ideally the one showing the `InitiatingProcessAccountName` column with `system`.)* |
| `screenshots/06-hr-collection.png` | Finding 6 — HR collection | The file-events screenshot showing `HR\Payroll\...`, `HR\Awards\quarterly_awards_shortlist`, and the `payroll_review_dpatel` file attributed to `j.morris`. *(Your Q13 screenshot.)* |

## Optional extras (if you want to add more)

These aren't referenced in the README yet, but you could add them for extra credit — just insert an `![caption](screenshots/filename.png)` line where relevant:

| Suggested filename | What it shows | Your source |
|---|---|---|
| `screenshots/05-invoice-fabrication.png` | The `FileCreated` → `FileRenamed` (PreviousFileName = "New Text Document.txt") → `FileModified` sequence proving the fake invoice was fabricated | Your Q10 evidence screenshot (the 4-row one with ActionType + PreviousFileName) |
| `screenshots/05-audit-tampering.png` | `review_audit_20260311.txt` modified by j.morris | Your Q11 screenshot |
| `screenshots/02-onedrive-noise.png` | The OneDrive `del`/`rmdir` commands hitting its own version folders, launched by `explorer.exe` | Your Q04 screenshot |

## How to reference an image in Markdown

```markdown
![Short caption describing the finding](screenshots/01-external-rdp-sources.png)
```

## Tips before you publish

- **Crop tight** — trim browser chrome and empty space so the query + results are the focus.
- **Redact nothing needed** — it's a simulated environment, so there's no real PII, but double-check no personal/local info is visible in your browser tabs or taskbar.
- **Consistent width** — screenshots that are roughly the same width look cleaner in a README.
- **Alt text matters** — the text in `[brackets]` is what screen readers and broken-image states show; keep it descriptive.
