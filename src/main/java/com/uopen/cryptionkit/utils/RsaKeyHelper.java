package com.uopen.cryptionkit.utils;
/**
 * Created by fplei on 2018/9/25.
 */

import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

/**
 * RSA秘钥对生成辅助
 * @author fplei
 * @create 2020-05-30-17:45
 * @email:1553234169@qq.com
 */
public class RsaKeyHelper {
    /** 密钥对生成器 */
    private static KeyPairGenerator keyPairGenerator = null;

    private static KeyFactory keyFactory = null;
    /** 缓存的密钥对 */
    private static KeyPair keyPair = null;
    private static final String ALGORITHM =  "RSA";
    /** 默认密钥大小 */
    private static final int KEY_SIZE = 2048;
    /** 初始化密钥工厂 */
    static{
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyFactory = KeyFactory.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * 构造RSA公钥
     * @param keyBytes 密钥数组
     * @return
     */
    public static RSAPublicKey getPublicKey(byte[] keyBytes){
        if(keyBytes==null){
            return null;
        }
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            return (RSAPublicKey)keyFactory.generatePublic(x509EncodedKeySpec);
        }catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 构造RSA私钥（RSAPrivateKey）
     * @param privateKey 密钥数组
     * @return
     */
    public static RSAPrivateKey getPrivateKey(byte[] privateKey){
        try {
            if(privateKey==null){
                return null;
            }
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
            return (RSAPrivateKey)keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 生成密钥对
     * 将密钥分别用Base64编码保存到#publicKey.properties#和#privateKey.properties#文件中
     * 保存的默认名称分别为publicKey和privateKey
     */
    public static synchronized KeyPass generateKeyPair(){
        try {
            keyPairGenerator.initialize(KEY_SIZE, new SecureRandom(UUID.randomUUID().toString().getBytes()));
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        String publicKeyString = new String(Base64.encode(rsaPublicKey.getEncoded()), Charset.forName("UTF-8"));
        String privateKeyString = new String(Base64.encode(rsaPrivateKey.getEncoded()), Charset.forName("UTF-8"));
        KeyPass keyPass=new KeyPass();
        keyPass.setPublicKey(publicKeyString);
        keyPass.setPrivateKey(privateKeyString);
        return keyPass;
    }

    public static class KeyPass{
        private String publicKey;
        private  String privateKey;

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKeyHex) {
            this.publicKey = publicKeyHex;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKeyHex) {
            this.privateKey = privateKeyHex;
        }

        /**
         * 保存到文件16进制
         * @param privateKeyFilePath 私钥保存文件路径
         * @param publicKeyFilePath 公密钥保存文件地址
         */
        public void saveToFile(String privateKeyFilePath,String publicKeyFilePath)throws Exception{
            if(StringUtils.isNull(privateKeyFilePath)||StringUtils.isNull(publicKeyFilePath)
                    ||publicKey==null||privateKey==null){
                throw new Exception("error:saveToFile function args invalid ?");
            }
            File privateKeyFile=new File(privateKeyFilePath);
            File publicKeyFile=new File(publicKeyFilePath);
            try{
                privateKeyFile.createNewFile();
                publicKeyFile.createNewFile();
            }catch (Exception e){
                e.printStackTrace();
            }
            FileWriter fileWriterPrivate=new FileWriter(privateKeyFile);
            fileWriterPrivate.write(privateKey);
            fileWriterPrivate.flush();
            fileWriterPrivate.close();

            FileWriter fileWriterPublic=new FileWriter(publicKeyFile);
            fileWriterPublic.write(publicKey);
            fileWriterPublic.flush();
            fileWriterPublic.close();
        }
    }
}
