# xss-validator

针对富文本类型 XSS 提交后端检测小工具。
---
## 背景
一次项目迭代需求需要对用户提交富文本不安全内容进行检测，且只需要检测提交文本内容是否包含恶意xss注入代码，
找遍市面上所有开源工具及方案后发现不太满足业务诉求，只会将不安全的标签进行清除返回，所以自己写了一个小工具,
所以这个小工具只做检测不做文本替换，也算提供一种解决思路。




---

## 代码处理思路

### 1. 解析富文本内容
- 使用 HTML 解析器（如 Jsoup）将富文本内容解析为 DOM 结构。
- 提取所有 HTML 标签和其属性。

### 2. 检查危险标签和属性
- **危险标签**：
    - `<script>`, `<iframe>`, `<frame>`, `<object>`, `<embed>`, `<applet>`, `<meta>`, `<link>`, `<style>` 等。
- **危险属性**：
    - `onload`, `onunload`, `onresize`, `onscroll`, `onfocus`, `onblur`, `onchange`, `onclick`, `ondblclick`,
      `onmousedown`, `onmouseup`, `onmouseover`, `onmouseout`, `onmousemove`, `onkeydown`, `onkeyup`,
      `onkeypress`, `onsubmit`, `onreset`, `onabort`, `onerror`, `onmessage`, `onstorage`, `onsuspend` 等。

### 3. 检测潜在的 XSS 代码
- 检查文本内容中是否包含潜在的 JavaScript 代码：
    - `javascript:`, `alert`, `prompt`, `confirm`, `document`, `window`, `location`, `innerHTML`, `outerHTML`,
      `execScript`, `setTimeout`, `setInterval` 等。
- 检查是否有 Base64 编码的脚本或其他编码方式隐藏的恶意代码。

### 4. 使用白名单机制
- 只允许特定的标签和属性通过，拒绝所有不在白名单中的标签和属性。
    - 示例允许标签：`<p>`, `<br>`, `<b>`, `<i>`, `<u>`, `<a>`, `<img>`, `<div>`, `<span>` 等。
    - 严格限制其属性。

### 5. 检测脚本执行
- 检查是否有 `src` 属性指向外部脚本文件（如 `.js` 文件）。
- 检查是否有 `href` 属性指向恶意 URL。
