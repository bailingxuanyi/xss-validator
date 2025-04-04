# xss-validator

针对富文本类型 XSS 提交后端检测小工具

---

## 处理思路

### 1. 解析富文本内容

- 使用 HTML 解析器（如 Jsoup）将富文本内容解析为 DOM 结构。
- 提取所有 HTML 标签和其属性。

---

### 2. 检查危险标签和属性

#### 危险标签
- `<script>`
- `<iframe>`
- `<frame>`
- `<object>`
- `<embed>`
- `<applet>`
- `<meta>`
- `<link>`
- `<style>`

#### 危险属性
- `onload`
- `onunload`
- `onresize`
- `onscroll`
- `onfocus`
- `onblur`
- `onchange`
- `onclick`
- `ondblclick`
- `onmousedown`
- `onmouseup`
- `onmouseover`
- `onmouseout`
- `onmousemove`
- `onkeydown`
- `onkeyup`
- `onkeypress`
- `onsubmit`
- `onreset`
- `onabort`
- `onerror`
- `onmessage`
- `onstorage`
- `onsuspend`

---

### 3. 检测潜在的 XSS 代码

- 检查文本内容中是否包含潜在的 JavaScript 代码，例如：
    - `javascript:`
    - `alert`
    - `prompt`
    - `confirm`
    - `document`
    - `window`
    - `location`
    - `innerHTML`
    - `outerHTML`
    - `execScript`
    - `setTimeout`
    - `setInterval`
- 检查是否有 Base64 编码的脚本或其他编码方式隐藏的恶意代码。

---

### 4. 使用白名单机制

- 只允许特定的标签和属性通过，拒绝所有不在白名单中的标签和属性。
    - **示例：**
        - 允许的标签：`<p>`, `<br>`, `<b>`, `<i>`, `<u>`, `<a>`, `<img>`, `<div>`, `<span>` 等。
        - 严格限制其属性，例如：
            - `<a>` 标签只允许 `href` 和 `target` 属性。
            - `<img>` 标签只允许 `src` 和 `alt` 属性。

---

### 5. 检测脚本执行

- 检查是否有 `src` 属性指向外部脚本文件（如 `.js` 文件）。
- 检查是否有 `href` 属性指向恶意 URL。
