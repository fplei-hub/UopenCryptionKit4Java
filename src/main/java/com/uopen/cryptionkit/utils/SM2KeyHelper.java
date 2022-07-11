package com.uopen.cryptionkit.utils;

import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.core.Sm2Cipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;

/**
 * SM2秘钥对生成辅助
 * @author fplei
 * @create 2020-05-30-17:45
 * @email:1553234169@qq.com
 */
public class SM2KeyHelper {

    //生成随机秘钥对
    public static KeyPair generateKeyPair(Sm2Cipher sm2Kit){
        if(sm2Kit==null){
            return null;
        }
        AsymmetricCipherKeyPair key = sm2Kit.ecc_key_pair_generator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();

        BigInteger privateKey = ecpriv.getD();
        ECPoint publicKey = ecpub.getQ();
        KeyPair keyPair=new KeyPair();
        if(sm2Kit.getReturnType().equals(ReturnType.TYPE_BASE64)){
            keyPair.setPublicKey(UUtils.convertToBase64(publicKey.getEncoded()));
            keyPair.setPrivateKey(UUtils.convertToBase64(privateKey.toByteArray()));
        }else {
            keyPair.setPublicKey(UUtils.byteArrayToHexString(publicKey.getEncoded()));
            keyPair.setPrivateKey(UUtils.byteArrayToHexString(privateKey.toByteArray()));
        }
        return keyPair;
    }

    public static class KeyPair{
        private String publicKey;
        private String privateKey;

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
    }
    //生成秘钥对
    public static void main(String args[]){
        try {
            Sm2Cipher sm2Cipher= new Sm2Cipher();
            sm2Cipher.setReturnDataType(ReturnType.TYPE_HEX);
            KeyPair keyPair= SM2KeyHelper.generateKeyPair(sm2Cipher);
            System.out.println("pri:"+keyPair.getPrivateKey());
            System.out.println("pub:"+keyPair.getPublicKey());
        }catch (Exception e){
            e.printStackTrace();
        }

    }
}
