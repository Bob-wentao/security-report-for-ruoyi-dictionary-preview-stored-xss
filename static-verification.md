# RuoYi 字典抽屉 cssClass 注入：静态可行性与版本范围核对

> 核对方式：只对照官方公开源码、发布标签和分支 HEAD。  
> 未搭建运行环境，未发送写入请求，未在浏览器中触发事件处理器。  
> 核对日期：2026-09-06。上游仓库：https://github.com/yangzongzhuan/RuoYi

## 合规边界

本次只做代码存在性与版本边界判断，不复现攻击。

可以确认的是：官方源码里是否存在报告描述的写入字段、过滤器行为和前端拼接 sink，以及这些代码从哪个标签/分支开始出现。  
不能替代的是：动态执行证明（会话写入、抽屉 DOM 出现事件属性、脚本在管理员上下文执行）。

## 静态结论

报告描述的代码路径在官方源码中成立，足以支持「存储型 XSS 代码可行性」这一判断。

1. `POST /system/dict/data/add` 接受 `SysDictData.cssClass`，校验只有 `@Size(max = 100)`，没有 class token 白名单。
2. 默认 `xss.enabled: true` 时，`/system/*` 仍会走 `EscapeUtil.clean()` / `HTMLFilter`。该过滤器在普通文本路径明确保留双引号。
3. v4.8.3 新增的 `renderDrawer()` 把 `cssClass` 直接拼进双引号包围的 `class` 属性，再交给 jQuery `.html()` 解析。
4. 因此，只要 `cssClass` 能带上属性分界字符并被原样读出，前端就会把它重新解释为额外 HTML 属性。这是属性上下文编码缺失，不是「过滤器被关闭」。

这是源码级可行性，不是本次动态复现结果。

## 本报告 sink 的影响范围

本报告的版本边界以 **字典类型页新增抽屉 `view()` / `renderDrawer()`** 为准。  
v4.8.2 及更早官方标签没有该函数，因此 **不属于本条抽屉漏洞的受影响发布版本**。

| 对象 | 提交 / 日期 | Java | Spring Boot | `renderDrawer()` 拼接 `cssClass` | 判定 |
| --- | --- | --- | --- | --- | --- |
| 标签 `v4.8.2` | `b16d50390ec3`（2025-12-13） | 8 | 2.5.15 | 无 | 不受本条影响 |
| 标签 `v4.8.1` 及更早 | 更早发布 | 见各标签 | 见各标签 | 无 | 不受本条影响 |
| 引入提交（master） | `33041ba96615`（2026-03-19） | — | — | 引入 | 引入点 |
| 引入提交（springboot2） | `266f9352297e`（2026-03-19） | — | — | 引入 | 引入点 |
| 引入提交（springboot3） | `4964f4e5be39`（2026-03-19） | — | — | 引入 | 引入点 |
| 标签 `v4.8.3` | `15e3a929ced9`（2026-03-23） | 17 | 4.0.3 | 有，与当前 master 相同 | **受影响发布版** |
| 当前 `master` | `3b3941abeb54`（2026-08-18） | 17 | 4.1.0 | 有，与 v4.8.3 相同 | **仍受影响（未发布修复）** |
| 当前 `springboot2` | `c772e17f2a2f`（2026-08-16） | 8 | 2.5.15 | 有，与 v4.8.3 相同 | **仍受影响** |
| 当前 `springboot3` | `9912eaeee1f8`（2026-08-18） | 17 | 3.5.16 | 有，与 v4.8.3 相同 | **仍受影响** |

补充：

- 官方标签列表到 `v4.8.3` 为止，没有更新的修复标签。
- `v4.8.3` 与当前 `master` / `springboot2` / `springboot3` 的 `renderDrawer()` 函数体逐字相同。
- `d2ed36e0`（2026-08-05，「优化前端代码防止注入风险」）只改了 `ry-ui.js`、`index.html`、`index-topnav.html`，**没有改字典抽屉**。
- 更新日志 v4.8.3 条目「优化字典类型列表新增抽屉效果详细信息」与引入提交一致；该版本没有对应修复说明。

建议写入 CVE / advisory 的受影响范围：

- 产品：RuoYi（Thymeleaf 单体版，https://github.com/yangzongzhuan/RuoYi）
- 受影响发布版本：`v4.8.3`
- 受影响未发布线：`master`、`springboot2`、`springboot3` 在 2026-03-19 引入提交之后、修复合并之前的全部快照
- 修复版本：公开仓库中尚未出现

## 运行环境含义

该 sink 是前端模板字符串拼接，不依赖某个特定 JDK 才能成立。环境差异只影响「哪条维护线会带上这段模板」：

| 维护线 | 典型运行环境 | 是否带抽屉 sink |
| --- | --- | --- |
| 官方 `v4.8.3` 发行包 / 当前 master | Java 17，Spring Boot 4.x，Thymeleaf，默认 `xss.enabled: true` | 是 |
| `springboot3` 分支 | Java 17，Spring Boot 3.5.x | 是 |
| `springboot2` 分支（2026-03-19 之后） | Java 8，Spring Boot 2.5.15 | 是 |
| 官方 `v4.8.2` 及更早发行包 | Java 8，Spring Boot 2.5.x（当时主线） | 否（无该抽屉） |

RuoYi-Vue / RuoYi-Vue3 是另一套前端，没有这份 `type.html` 抽屉实现，**不能按同一文件判定为受影响**。它们是否另有字典字段拼接问题，不在本报告范围内。

默认配置不会切断这条路径：`xss.enabled` 默认为 `true`，且 `/system/*` 在过滤名单内；过滤器保留双引号，所以默认开 XSS 过滤并不能当修复。`csrf.enabled` 默认 `false`，只影响写入请求是否还要带 CSRF 头，不改变 sink。

## 与报告逐条对照

| 报告主张 | 静态核对结果 |
| --- | --- |
| 写入入口是 `SysDictDataController.addSave`，权限 `system:dict:add` | 与当前源码一致 |
| `cssClass` 只有长度限制 | `@Size(min = 0, max = 100)` 在 v4.8.2 起即存在，v4.8.3 / 三分支 HEAD 未增加白名单 |
| `HTMLFilter.encodeQuotes` 保留双引号 | 当前源码仍有「不替换双引号为 `&quot;`，防止 json 格式无效」 |
| v4.8.3 新增抽屉并把 `cssClass` 拼进 `<span class="...">` | 官方源码行位与报告一致（约 228–240 行），随后 `$("#drawerBody").html(html)` |
| v4.8.2 无该抽屉 | `v4.8.0`–`v4.8.2` 的 `type.html` 均无 `renderDrawer` |
| 测试提交 `3b3941abeb54` | 即当前 `origin/master` HEAD，sink 仍在 |
| 已有修复版本 | 公开标签和三分支 HEAD 均未修复该处 |

## 相关但超出本条版本边界的代码

以下位置同样把 `cssClass` 拼进 HTML `class` 属性，出现时间早于抽屉，**不应并进本条「v4.8.3 引入」的版本范围**。厂商修抽屉时建议一并改为安全 DOM API，避免同字段换页面仍可被解释为属性。

- `ruoyi-admin/src/main/resources/templates/system/dict/data/data.html`：字典数据列表 formatter
- `ruoyi-admin/src/main/resources/static/ruoyi/js/ry-ui.js`：`selectDictLabel` 一类展示逻辑

这两处从至少 `v4.7.9` 起就能看到同类拼接。它们是加固建议，不是本条 CVE 的已证实影响版本。

## 厂商侧如何做合规验证（无攻击载荷）

作者或 CVE 分配方可以用下面方式完成验证，不必复现攻击脚本：

1. 确认目标提交包含 `function renderDrawer`，且存在 `labelHtml = '<span class="' + r.cssClass + '">'` 后接 `.html(html)`。
2. 确认 `SysDictData.getCssClass()` 仍只有长度注解。
3. 确认 `HTMLFilter.encodeQuotes` 仍保留双引号。
4. 修复后做防御性回归：合法 class token（如 `label-success`）显示不受影响；渲染结果不得把用户字段当作额外 HTML 属性解析。回归断言应检查「输出只能是 class token」，不要在测试里放置事件处理器载荷。

建议修复方向与原报告一致：用 `document.createElement` / `textContent` / `className` 建节点；服务端将 `cssClass` 限制为 `[A-Za-z0-9_-]` 一类 token；不要依赖通用请求过滤器做属性编码。
