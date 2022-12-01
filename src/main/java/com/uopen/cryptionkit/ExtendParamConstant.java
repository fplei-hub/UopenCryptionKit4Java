package com.uopen.cryptionkit;

/**
 * 额外拓展参数KEY
 * @author fplei
 * @create 2022-11-30-17:45
 */
public class ExtendParamConstant {
    public static class KeyName{
        //模式KEY ,值代表
        public static final String MODE="MODE";
        //填充模式KEY
        public static final String PADDING="PADDING";
        //AES向量
        public static final String IV="IV";
    }
    public static class KeyValue{
        public static final String MODE_ECB="ECB";
        public static final String MODE_CBC="CBC";
        public static final String MODE_PCBC="PCBC";
        public static final String MODE_CFB="CFB";
        public static final String MODE_CTR="CTR";

        public static final String PADDING_PKCS7="PKCS7Padding";
        public static final String PADDING_PKCS5="PKCS5Padding";
        public static final String PADDING_NO="NoPadding";
    }

}
