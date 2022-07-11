package com.uopen.cryptionkit;


import com.uopen.cryptionkit.core.*;

/**
 * 注册
 */
public enum CipherRegister {
    Cipher_Aes(AesCipher.class, "AES加解密"),

    Cipher_HmaSHa1(HmacSHA1Cipher.class, "HmacSha1指纹"),

    Cipher_HmacSha256(HmacSHA256Cipher.class, "HmacSHA256指纹"),

    Cipher_Des(DesCipher.class,"DES加解密"),

    Cipher_TripleDes(TripleDesCipher.class, "3DES加解密"),

    Cipher_Md5(Md5Signature.class, "MD5指纹"),

    Cipher_RsaPublic(RsaPublicCipher.class, "RSA公钥加解密器"),

    Cipher_RsaPrivate(RsaPrivateCipher.class, "RSA私钥加解密器"),

    Cipher_Sm3(Sm3Signature.class,"国秘SM3签名"),

    Cipher_Sm2(Sm2Cipher.class,"国秘SM2非对称加解密"),

    Cipher_Sm4(Sm4Cipher.class,"国秘SM4对称加解密");

    private Class clazz;
    private String des;

    CipherRegister(Class mClazz, String mDes) {
        this.clazz = mClazz;
        this.des = mDes;
    }

    public Class getClazz() {
        return clazz;
    }

    public void setClazz(Class clazz) {
        this.clazz = clazz;
    }

    public String getDes() {
        return des;
    }

    public void setDes(String des) {
        this.des = des;
    }
}
