package com.uopen.cryptionkit.key;


/**
 * 秘钥管理器，希望对外使用将秘钥传输和加密过程分开，具体使用到哪些算法重写对应秘钥获取即可
 * @author fplei
 * @create 2020-05-30-17:45
 * @email: 1553234169@qq.com
 */
public abstract class KeyCreator {
    /**
     * AES秘钥
     * @return
     */
    public String getAesPass() {
        return null;
    }

    /**
     * 获取Des秘钥
     * @return
     */
    public String getDesPass(){
        return null;
    }
    /**
     * 注意：3DES秘钥，长度最好固定24个字符，否则不足将会自动追加补0,超出会自动截断
     * @return
     */
    public String getTriplePass() {
        return null;
    }
    /**
     * 公钥可通过{RsaKeyHelper.java}生成，内置默认使用Base64字符串作为铭文秘钥，如果需要更换，需要生成其他的数据类型，并且调整{RsaPrivateCipher.java/RsaPublicCipher}加密器的秘钥编码方式
     * @return
     */
    public String getRsaPrivatePass() {
        return null;
    }

    /**
     * 私钥可通过{RsaKeyHelper.java}生成，内置默认使用Base64字符串作为铭文秘钥，如果需要更换，需要生成其他的数据类型，并且调整{RsaPrivateCipher.java/RsaPublicCipher}加密器的秘钥编码方式
     * @return
     */
    public String getRsaPublicPass() {
        return null;
    }

    /**
     * 加签名秘钥，随意
     * @return
     */
    public String getHmacShaPass() {
        return null;
    }

    /**
     * 公钥可通过{SM2KeyHelper.java}生成，内置默认使用十六进制字符串作为铭文秘钥，如果需要更换，需要生成其他的数据类型，并且调整{Sm2Cipher.java}加密器的秘钥编码方式
     * @return
     */
    public String getSm2PublicPass(){return null;}

    /**
     * 私钥可通过{SM2KeyHelper.java}生成，内置默认使用十六进制字符串作为铭文秘钥，如果需要更换，需要生成其他的数据类型，并且调整{Sm2Cipher.java}加密器的秘钥编码方式
     * @return
     */
    public String getSm2PrivatePass(){return null;}

    /***
     * 需要注意的是：国密SM4秘钥长度为16个字符
     */
    public String getSm4Pass(){
        return null;
    }

    /**
     * 获取DSA签名私钥
     * @return
     */
    public String getDasPrivateKey(){return null;}

    /**
     * 获取DAS签名验证公钥
     * @return
     */
    public String getDasPublicKey(){return null;}
}
