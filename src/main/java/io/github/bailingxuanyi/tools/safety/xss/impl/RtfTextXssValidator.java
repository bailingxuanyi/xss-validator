package io.github.bailingxuanyi.tools.safety.xss.impl;


import io.github.bailingxuanyi.tools.safety.xss.api.XssValidator;
import io.github.bailingxuanyi.tools.safety.xss.api.result.UnsafeElement;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.*;
import org.jsoup.select.NodeVisitor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 针对富文本类型xss提交后端检测小工具
 */
@Slf4j
public class RtfTextXssValidator implements XssValidator, InitializingBean {
    /**
     * 富文本内容xss检测，白名单 只允许在富文本里使用以下标签 如:
     * <a> <b> <div> <span> <em> <i> <p> <h1> <h2> <h3> <h4> <h5> <h6> <blockquote> <code> <pre> <ol> <ul> <li> <hr> <strong>
     *  若黑白名单一起配置，则只有白名单生效
     */
    @Value("#{'${rtf.xss.validator.html.onlySupportedTags:}'.split(',').![trim()]}")
    private Set<String> onlySupportedTags;

    /**
     * 富文本内容xss检测，黑名单 被禁止使用的html标签 如<svg></svg> <script></script>
     */
    @Value("#{'${rtf.xss.validator.html.notAllowedTags:}'.split(',').![trim()]}")
    private Set<String> notAllowedTags;

    /**
     * 富文本内容xss检测，被禁止使用的html标签的属性 attr_key
     */
    @Value("#{'${rtf.xss.validator.html.notAllowedAttributes:}'.split(',').![trim()]}")
    private Set<String> notAllowedAttrs = Sets.newHashSet();

    /**
     * 富文本内容xss检测，html标签属性value若包含以下关键字单词不允许落库
     * (?i)(alert|confirm|msgbox|eval|settimeout|setinterval|function|window|self|document|base64|script|newline|javascript)
     */
    @Value("${rtf.xss.validator.html.notAllowedWords.regex.expression:(?i)(alert|confirm|msgbox|eval|settimeout|setinterval|function|window|self|document|base64|script|newline|javascript)")
    private String notAllowedAttrValueRegexExpression;

    /**
     * 自定义危险的标签属性；扫描标签属性的 attr_value，这些 value 是可能会被注入的，需要进行检测的,
     * 如<a href="javascript:alert(1)"> href 可能存在注入情况
     * 如<a src="javascript:alert(1)"> src 可能存在注入情况
     */
    @Value("#{'${rtf.xss.validator.html.dangerousAttributes:}'.split(',').![trim()]}")
    private Set<String> dangerousAttrs = Sets.newHashSet();

    /**
     * 自定义危险的标签；
     * 扫描这些标签的所有属性attr_key 对应的 attr_value，这些value 是可能会被注入的，需要进行检测的，
     * 如：
     * <a onload='xxx', onclick='yyy'></a>
     * 会对其属性的 value xxx, yyy  进行检测
     */
    @Value("#{'${rtf.xss.validator.html.dangerousTags:}'.split(',').![trim()]}")
    private Set<String> dangerousTags = Sets.newHashSet();

    /**
     * xss校验的全局开关，是否开启进行xss校验，允许勿拦截情况下放权让业务往下走不阻塞
     * 需要配合apollo配置中心进行配置管理生效
     */
    @Value("${rtf.xss.validator.html.enable:true}")
    private Boolean xssEnable = true;

    /**
     * 是否对JJEncode混淆特征检测
     */
    @Value("${rtf.xss.validator.html.enable.jjEncode.check:true}")
    private Boolean enableJJEncodeCheck;

    /**
     * 是否对AAEncode混淆特征检测
     */
    @Value("${rtf.xss.validator.html.enable.aaEncode.check:true}")
    private Boolean enableAAEncodeCheck;

    /**
     * 是否对Jsfuck混淆特征检测
     */
    @Value("${rtf.xss.validator.html.enable.jsfuck.check:true}")
    private Boolean enableJsfuckCheck;

    /**
     * 正则表达式
     */
    private Pattern dagerousWordsPattern;

    /**
     * AAEncode 检测js混淆代码
     */
    Pattern aaJsPattern = Pattern.compile("[\\uFF9F-\\uFFEF\\u3000-\\u303F]+|ﾟωﾟﾉ|=\\s*_=\\s*\\d+;");


    // JJEncode 检测js混淆代码
    Pattern jjPattern = Pattern.compile(
            "\\$=~\\[\\];\\$=\\{___:\\+\\+\\$|" +
                    "_=~\\[\\];_=\\{___:\\+\\+_|" +
                    "[\\$+!_\\[\\]]{15,}|" +
                    "(\\$|_)\\s*=\\s*\\{\\s*___\\s*:\\s*\\+\\+(\\$|_)");


    /**
     * 验证富文本，返回不安全的标签（默认第一个）
     *
     * @param rtfContent 富文本内容
     */
    public Optional<UnsafeElement> validate(String rtfContent) {
        try {
            if (xssEnable == null || !xssEnable) {
                return Optional.empty();
            }
            return doValidateUnsafeElements(rtfContent, 1).stream().findFirst();
        } catch (Exception e) {
            log.error("[Xss检测] 检查xss失败, 异常不拦截放权通过, content:{}, exception:", rtfContent, e);
        }
        return Optional.empty();
    }

    @Override
    public List<UnsafeElement> validate(String rtfContent, int returnMaxUnsafeElements) {
        try {
            if (xssEnable == null || !xssEnable) {
                return Collections.emptyList();
            }
            return doValidateUnsafeElements(rtfContent, returnMaxUnsafeElements);
        } catch (Exception e) {
            log.error("[Xss检测] 检查xss失败, 异常不拦截放权通过, content:{}, exception:", rtfContent, e);
        }
        return Collections.emptyList();
    }

    /**
     * 验证富文本，返回不安全的标签集合
     *
     * @param content           内容
     * @param returnMaxElements 限制返回数量 检测出100个不安全的元素，允许只返回一个
     * @return
     */
    private List<UnsafeElement> doValidateUnsafeElements(String content, int returnMaxElements) {
        Document document = Jsoup.parseBodyFragment(content);
        Queue<UnsafeElement> unsafeElements = new LinkedBlockingQueue<>(returnMaxElements);
        document.body().traverse(new NodeVisitor() {
            @Override
            public void head(Node node, int i) {
                if (node instanceof Element) {
                    Element element = (Element) node;
                    // 检查是否为不安全的标签
                    if (hasUnsafeElement(element)) {
                        unsafeElements.offer(new UnsafeElement(element, i));
                    }
                }
            }
        });
        return Lists.newArrayList(unsafeElements);
    }

    private boolean hasUnsafeAttrValue(Element element) {
        if (element.attributes() == null) {
            return false;
        }
        String tagName = element.tagName();
        Attributes attributes = element.attributes();
        for (Attribute attribute : attributes) {
            if (attribute == null) {
                continue;
            }
            // 判断是否危险标签或属性
            if (dangerousAttrs.contains(StringUtils.lowerCase(attribute.getKey()))
                    || dangerousTags.contains(StringUtils.lowerCase(tagName))) {
                if (attribute.getValue() == null) {
                    continue;
                }
                //转义 &# 开头十六进制字符
                String decodedValue = org.apache.commons.text.StringEscapeUtils.unescapeHtml4(attribute.getValue()).toLowerCase();
                //转义 /u 开头java unicode字符
                decodedValue = StringEscapeUtils.unescapeJava(decodedValue);
                //替换所有 \n\t 符号
                decodedValue = StringUtils.replaceAll(decodedValue, "\\s+", "");

                // jsfuck 特征检测
                if (enableJsfuckCheck && containJsFuckChar(decodedValue)) {
                    log.info("[xss检测] jsfuck特征检测不通过, element:{}", element.toString());
                    return true;
                }

                //aaEncode 特征检测
                if (enableAAEncodeCheck && containAAEncodeChar(decodedValue)) {
                    log.info("[xss检测] aaEncode特征检测不通过, element:{}", element.toString());
                    return true;
                }

                //jjEncode特征检测
                if (enableJJEncodeCheck && containJJEncodeChar(decodedValue)) {
                    log.info("[xss检测] jjEncode特征检测不通过, element:{}", element.toString());
                    return true;
                }

                if (dagerousWordsPattern == null) {
                    log.info("[xss检测] pattern编译失败，跳过value检测，notAllowedJsKeyWordsRegexPattern:{}", notAllowedAttrValueRegexExpression);
                    return false;
                }

                //危险关键字检测
                Matcher matcher = dagerousWordsPattern.matcher(decodedValue);
                if (matcher.find()) {
                    return true;
                }

            }
        }

        return false;
    }

    private boolean hasUnsafeTagName(Element element) {
        if (element == null) {
            return false;
        }
        if (element.tagName() == null) {
            return false;
        }
        // 判断是否危险标签 如果未配置白名单则使用黑名单进行过滤
        if (CollectionUtils.isEmpty(onlySupportedTags)) {
            return notAllowedTags.contains(StringUtils.lowerCase(element.tagName()));
        }

        return !onlySupportedTags.contains(StringUtils.lowerCase(element.tagName()));

    }

    private boolean hasUnsafeAttrKey(Element element) {
        if (element == null) {
            return false;
        }

        if (element.attributes() == null) {
            return false;
        }
        for (String forbiddenAttr : notAllowedAttrs) {
            if (element.hasAttr(StringUtils.lowerCase(forbiddenAttr))) {
                return true;
            }
        }
        return false;
    }

    private boolean hasUnsafeElement(Element element) {
        if (element == null) {
            return false;
        }
        //不安全的标签前缀检测
        if (hasUnsafeTagName(element)) {
            return true;
        }

        //不安全标签属性检测
        if (hasUnsafeAttrKey(element)) {
            return true;
        }

        //不安全的标签属性值检测
        if (hasUnsafeAttrValue(element)) {
            return true;
        }

        return false;
    }


    @Override
    public void afterPropertiesSet() throws Exception {
        //初始化正则表达
        resetPattern();
    }

    public void resetPattern() {
        try {
            this.dagerousWordsPattern = Pattern.compile(notAllowedAttrValueRegexExpression, Pattern.CASE_INSENSITIVE);
            log.info("[Xss检测]notAllowedJsKeyWordsRegexPattern编译成功, notAllowedAttrValueRegexExpression:{}", notAllowedAttrValueRegexExpression);
        } catch (Exception e) {
            log.error("[Xss检测] notAllowedJsKeyWordsRegexPattern编译失败 notAllowedJsKeyWordsRegexPattern:{}", notAllowedAttrValueRegexExpression);
        }
    }


    public void setNotAllowedTags(Set<String> notAllowedTags) {
        this.notAllowedTags = notAllowedTags;
    }

    public void setNotAllowedAttrs(Set<String> notAllowedAttrs) {
        this.notAllowedAttrs = notAllowedAttrs;
    }

    public void setNotAllowedAttrValueRegexExpression(String notAllowedAttrValueRegexExpression) {
        this.notAllowedAttrValueRegexExpression = notAllowedAttrValueRegexExpression;
    }

    public void setDangerousAttrs(Set<String> dangerousAttrs) {
        this.dangerousAttrs = dangerousAttrs;
    }


    /**
     * 判断是否为 jsFuck特征 混淆代码
     *
     * @param input
     */
    public static boolean containJsFuckChar(String input) {
        return StringUtils.containsAny(input, "[]()+!")
                && StringUtils.countMatches(input, "[") > 10;
    }

    /**
     * 判断是否包含AAEncode特征 混淆代码
     *
     * @param input
     */
    public boolean containAAEncodeChar(String input) {
        return aaJsPattern.matcher(input).find();
    }


    /**
     * 判断是否包含JJEncode特征 混淆代码
     *
     * @param input
     */
    public boolean containJJEncodeChar(String input) {
        // 检查特殊字符比例
        long specialCharCount = input.chars()
                .filter(c -> c == '$' || c == '_' || c == '+' || c == '!' || c == '[' || c == ']')
                .count();
        double ratio = (double) specialCharCount / input.length();
        if (ratio > 0.6) {
            return true;
        }
        return jjPattern.matcher(input).find();
    }

    public void setEnableJJEncodeCheck(Boolean enableJJEncodeCheck) {
        this.enableJJEncodeCheck = enableJJEncodeCheck;
    }

    public void setEnableAAEncodeCheck(Boolean enableAAEncodeCheck) {
        this.enableAAEncodeCheck = enableAAEncodeCheck;
    }

    public void setEnableJsfuckCheck(Boolean enableJsfuckCheck) {
        this.enableJsfuckCheck = enableJsfuckCheck;
    }


}
