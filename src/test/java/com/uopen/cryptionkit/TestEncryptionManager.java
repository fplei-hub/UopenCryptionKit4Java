package com.uopen.cryptionkit;


import com.uopen.cryptionkit.utils.RsaKeyHelper;

public class TestEncryptionManager {
    //for test
    public static void main(String[] args) {

        RsaKeyHelper.KeyPass keyPass= RsaKeyHelper.generateKeyPair();
        System.out.println("公钥："+keyPass.getPublicKey());
        System.out.println("私钥："+keyPass.getPrivateKey());

        String value = UEncryptionManager.getInstance().withAesPck7("123456", Op.Encryption, ReturnType.TYPE_BASE64);
        System.out.println("AES加密后值：" + value);
        String value1 = UEncryptionManager.getInstance().withAesPck7(value, Op.Decrypt, ReturnType.TYPE_BASE64);
        System.out.println("AES解密后值：" + value1);
        String sign256Base64 = UEncryptionManager.getInstance().withHmacSh256("测试字符串asa@!_a", ReturnType.TYPE_HEX);
        System.out.println("HmacSh256 指纹：" + sign256Base64);
        String sign1Base64 = UEncryptionManager.getInstance().withHmacSha1("测试字符串asa@!_a", ReturnType.TYPE_HEX);
        System.out.println("HmacSha1 指纹：" + sign1Base64);
        String md5 = UEncryptionManager.getInstance().withMd5("哈哈杀死a123456", ReturnType.TYPE_BASE64);
        System.out.println("md5 指纹：" + md5);
        String triple1 = UEncryptionManager.getInstance().withTripleDes("测试3des加解密字符串@(*!*@&!__", Op.Encryption, ReturnType.TYPE_BASE64);
        System.out.println("3DES加密：" + triple1);
        String triple2 = UEncryptionManager.getInstance().withTripleDes(triple1, Op.Decrypt, ReturnType.TYPE_BASE64);
        System.out.println("3DES解密：" + triple2);
        //生成2048位rsa密钥对
        //RsaPrivateCipher.KeyPairHelper.generateKeyPair();
        //公钥加密--》私钥解密
        String rsaPublic = UEncryptionManager.getInstance().withRsaPublic("测试RSA公钥加解密!@823144aas_*!.>", Op.Encryption, ReturnType.TYPE_BASE64);
        System.out.println("RSA公钥加密：" + rsaPublic);
        String rsaPublic1 = UEncryptionManager.getInstance().withRsaPrivate(rsaPublic, Op.Decrypt, ReturnType.TYPE_BASE64);
        System.out.println("RSA私钥解密：" + rsaPublic1);

        //私钥加密---》公钥解密
        String rsaPrivate = UEncryptionManager.getInstance().withRsaPrivate("测试RSA私钥主导加解密@!@!@!&@*!.>", Op.Encryption, ReturnType.TYPE_HEX);
        System.out.println("RSA私钥加密：" + rsaPrivate);
        String rsaPrivate1 = UEncryptionManager.getInstance().withRsaPublic(rsaPrivate, Op.Decrypt, ReturnType.TYPE_HEX);
        System.out.println("RSA公钥解密：" + rsaPrivate1);

        //SM3签名
        String sm3Sign= UEncryptionManager.getInstance().withSm3("测试Sm3签名算法",ReturnType.TYPE_HEX);
        System.out.println("国秘SM3签名：" + sm3Sign);

        //SM4加解密-秘钥为16字符长度
        String sm4Encry= UEncryptionManager.getInstance().withSm4("测试Sm4对称加密算法——_90a8^$",Op.Encryption,ReturnType.TYPE_BASE64);
        System.out.println("国秘SM4加密：" + sm4Encry);
        String sm4Decry= UEncryptionManager.getInstance().withSm4(sm4Encry,Op.Decrypt,ReturnType.TYPE_BASE64);
        System.out.println("国秘SM4解密：" + sm4Decry);

        //公钥加密--》私钥解密
        String sm2PublicKeyEncry= UEncryptionManager.getInstance().withSm2PublicKey("这是测试Sm2公钥加密私钥解密的内容）*（*&*&",Op.Encryption,ReturnType.TYPE_HEX);
        System.out.println("SM2公钥加密：" + sm2PublicKeyEncry);
        String sm2PrivateKeyDecry= UEncryptionManager.getInstance().withSm2PrivateKey(sm2PublicKeyEncry,Op.Decrypt,ReturnType.TYPE_HEX);
        System.out.println("SM2私钥解密：" + sm2PrivateKeyDecry);

        // DSA加签与验证
        String dasResult= UEncryptionManager.getInstance().withDasSign("等待Das加签的数据",ReturnType.TYPE_BASE64);
        System.out.println("DSA加签：" + dasResult);
        Boolean dasFlag= UEncryptionManager.getInstance().withDasVerify("等待Das加签的数据",dasResult,ReturnType.TYPE_BASE64);
        System.out.println("DSA公钥签名验证：" + dasFlag);
    }
}
