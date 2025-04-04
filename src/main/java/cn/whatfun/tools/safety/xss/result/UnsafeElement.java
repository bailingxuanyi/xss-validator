package cn.whatfun.tools.safety.xss.result;

import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.nodes.Element;

/**
 * 不安全的标签元素
 */
@Getter
public class UnsafeElement {
    /**
     * jsoup element元素
     */
    private Element jsoupElement;

    /**
     * 元素深度
     */
    private int depth;

    /**
     * 不安全的 html 标签值
     */
    private String unsafeHtml;

    public UnsafeElement(Element jsoupElement, int depth) {
        this.jsoupElement = jsoupElement;
        this.depth = depth;
        this.unsafeHtml =StringUtils.replaceAll(jsoupElement.toString(), "[\\r\\n]+", "");
    }
}
