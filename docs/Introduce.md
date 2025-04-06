## 1.工程中 pom.xml 引入 maven 依赖

```
<dependency>
   <groupId>io.github.bailingxuanyi</groupId>
   <artifactId>xss-validator</artifactId>
   <version>1.0.1-RELEASE</version>
</dependency>

```

## 2. application.xml 定义、增加下列配置项

```
##
#  白名单 只允许在富文本里使用以下标签 如:
#  <a> <b> <div> <span> <em> <i> <p> <h1> <h2> <h3> <h4> <h5> <h6> <blockquote> <code> <pre> <ol> <ul> <li> <hr> <strong>
#  若黑白名单一起配置，则只有白名单生效，非白名单里的标签都会被检测提示不安全
rtf.xss.validator.html.onlySupportedTag = a,b,div,span,em,i,p,h1,h2,h3,h4,h5,h6,blockquote,code,pre,ol,ul,li,hr,strong

##
# 被禁止使用的html标签属性集合
# 如：<a href="xxx", onload="yyy"> 当onload属性被配置时，该标签会被检测提示不安全
rtf.xss.validator.html.notAllowedTags = onclick,onmouseover,onmouseout,onmousedown,onmouseup,onmousemove,onmousewheel,onclick,ondblclick,onchange,onblur,onfocus,onkeydown,onkeypress,onkeyup,onload,onunload,onabort,onerror,onresize,onscroll,onselect,onblur,onchange,onfocus,onreset,onselect,onsubmit,onkeydown,onkeypress,onkeyup,onmouseover,onmouseout,onmousemove,onmouseup,onmousedown,onclick


##
# 虽然我们定义了标签的白名单，但是这些白名单的标签的属性也有可能会存在被注入的情况
#
# 自定义危险的标签
# 代码会扫描这些标签属性 attr_key 对应的 attr_value，这些value 是可能会被注入的，需要进行检测，定义后可以配置对应的属性值进行检测
# 如<img src="javascript:alert(1)"> src 可能存在注入情况
# 如:<a href="javascript:alert(1)"> href 可能存在注入情况
#
rtf.xss.validator.html.dangerousAttributes = src, href, style, data


##
# 危险的标签属性的属性值进行正则表达式匹配检测， 如果存在关键字则返回检测不通过
#
rtf.xss.validator.html.notAllowedWords.regex.expression = (?i)(alert|confirm|msgbox|eval|settimeout|setinterval|function|window|self|document|base64|script|newline|javascript)

```



## 3.spring bean 容器注入及初始化

``` 
@Configuration
public class XssConfiguration {
    @Bean("xssValidator")
    public XssValidator xssValidator() {
        return new RtfTextXssValidator();
    }
}
```



