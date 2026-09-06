# RuoYi 4.8.3 Dictionary Preview Stored XSS

English security advisory and lab proof of concept for a stored XSS issue in RuoYi 4.8.3.

The dictionary-data drawer preview added in v4.8.3 inserts a persisted `cssClass` value into an HTML attribute. A low-privilege account with `system:dict:add` can store an event handler. Opening the preview and hovering the malicious label executes the script in the victim's RuoYi admin session.

## Files

| File | Purpose |
|---|---|
| [security-report-ruoyi-4.8.3-dictionary-preview-stored-xss.md](security-report-ruoyi-4.8.3-dictionary-preview-stored-xss.md) | Full English advisory for maintainers / CNA / VulDB |
| [poc/README.md](poc/README.md) | Standalone lab PoC for the VulDB exploit field |
| [vuldb-submission.md](vuldb-submission.md) | Copy-paste text for the VulDB web form |
| [security-report.md](security-report.md) | Original Chinese report |

## Affected

- Product: RuoYi (monolithic, Spring Boot + Shiro)
- Version: 4.8.3
- Commit: `3b3941abeb5402297e5b4de82a30e6471c2239f3`
- Write route: `POST /system/dict/data/add`, parameter `cssClass`
- Preview route: `/system/dict` drawer `view(dictId)` / `renderDrawer()`
- Sink: `ruoyi-admin/src/main/resources/templates/system/dict/type/type.html`
- CWE: CWE-79 Cross-site Scripting
- CVSS 3.1 reference: `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.3)

## VulDB note

VulDB does not require two uploaded files, but the web form treats the vulnerability summary and the exploit/PoC as different content. Use the advisory for product, version, CWE, root cause, and impact. Use `poc/README.md` for the exploit field.

Source: <https://vuldb.com/kb/submission>
