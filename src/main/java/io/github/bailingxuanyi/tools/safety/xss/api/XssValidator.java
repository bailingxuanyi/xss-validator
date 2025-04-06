package io.github.bailingxuanyi.tools.safety.xss.api;

import io.github.bailingxuanyi.tools.safety.xss.api.result.UnsafeElement;

import java.util.List;
import java.util.Optional;

/**
 * 一个简单的xss富文本校验器
 */
public interface XssValidator {

    /**
     * 验证富文本，返回不安全的标签（默认第一个不安全的元素）
     *
     * @param rtfContent 富文本内容
     */
    Optional<UnsafeElement> validate(String rtfContent);


    /**
     * 验证富文本，返回不安全的标签集合
     * @param rtfContent 富文本内容
     * @param returnMaxUnsafeElements 允许返回的不安全标签最多数量
     *                                如果需要返回全部元素，则传入 Integer.MAX_VALUE
     *
     */
    List<UnsafeElement> validate(String rtfContent, int returnMaxUnsafeElements);
}
