package com.uopen.cryptionkit;

/**
 * 签名器
 */
public interface USignature {
    default ReturnType defaultReturnDataType() {
        return ReturnType.TYPE_HEX;
    }

    void setReturnDataType(ReturnType returnType);

    /**
     * 签名
     *
     * @param content 内容
     * @return 返回原始bytes
     */
    byte[] sign(byte[] content);

    /**
     * 签名
     * @param privateKey 私钥
     * @param content 内容
     * @return
     */
    byte[] signByKey(byte[] privateKey,byte[] content);
    /**
     * 签名
     * @param privateKey 私钥
     * @param content 内容
     * @return
     */
    String signByKey(String privateKey,String content);
    /**
     * 签名验证
     * @param publicKey 公钥
     * @param data 数据体
     * @param sign 签名
     * @return
     */
    boolean verify(String publicKey,String data,String sign);
    /**
     * 签名 默认返回String
     *
     * @param content
     * @return 根据设置的返回类型返回对应编码的字符串
     */
    String signToString(String content);

    /**
     * 签名
     *
     * @param content 内容
     * @return 返回Base64字符串
     */
    String signToBase64(String content);

    /**
     * 签名
     *
     * @param content 内容
     * @param isUpper 是否大写
     * @return 返回16进制字符串
     */
    String signToHexString(String content, boolean isUpper);
}
