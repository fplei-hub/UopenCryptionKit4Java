package com.uopen.cryptionkit;

import java.util.HashMap;

/**
 * 加密器
 */
public interface UCipher {
    default ReturnType defaultReturnDataType() {
        return ReturnType.TYPE_HEX;
    }

    void setReturnDataType(ReturnType returnType);

    /**
     * 设置额外参数，参数Key见
     * @param extendParams
     */
    void setExtendParams(HashMap<String,String> extendParams);
    /**
     * 加密
     *
     * @param key
     * @param content
     * @return 返回原始byte[]
     */
    byte[] encode(String key, byte[] content) throws Exception;

    /**
     * 加密，智能返回对应类型，根据设置的returnType类型
     *
     * @param key
     * @param content
     * @return 智能返回对应类型，根据设置的returnType类型
     */
    String encode(String key, String content) throws Exception;

    /**
     * 加密返回Base64
     *
     * @param key
     * @param content
     * @return 返回Base64
     */
    String encodeToBase64(String key, String content) throws Exception;

    /**
     * 加密
     *
     * @param key
     * @param content
     * @return 返回结果为16进制
     */
    String encodeToHexString(String key, String content) throws Exception;

    /**
     * 解密
     *
     * @param key
     * @param content
     * @return
     */
    byte[] decode(String key, byte[] content) throws Exception;

    /**
     * 解密，智能返回对应类型，根据设置的returnType类型
     *
     * @param key
     * @param content
     * @return 智能返回对应类型，根据设置的returnType类型
     */
    String decode(String key, String content) throws Exception;

    /**
     * 解密
     *
     * @param key
     * @param contentBase64 传入base64加密值
     * @return
     */
    String decodeByBase64(String key, String contentBase64) throws Exception;

    /**
     * 解密
     *
     * @param key
     * @param contentHex 传入hexString 加密值
     * @return
     */
    String decodeByHexString(String key, String contentHex) throws Exception;
}
