package com.uopen.cryptionkit.utils;

import com.uopen.cryptionkit.ReturnType;
import java.io.File;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * DSA秘钥对生成辅助
 * @author fplei
 * @create 2020-05-30-17:45
 * @email:1553234169@qq.com
 */
public class DSAKeyHelper {
    public static final String KEY_ALGORITHM = "DSA";
    public static final int KEY_SIZE=1024;
    public static class KeyPass{
        //16位编码公钥
        private String publicKey;
        //16位编码私钥
        private  String privateKey;

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

        //密钥保存到文件
        public void saveToFile(String privateKeyFilePath,String publicKeyFilePath)throws Exception{
            if(StringUtils.isNull(privateKeyFilePath)||StringUtils.isNull(publicKeyFilePath)
                    ||StringUtils.isNull(this.privateKey)||StringUtils.isNull(this.publicKey)){
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
            fileWriterPrivate.write(this.privateKey);
            fileWriterPrivate.flush();
            fileWriterPrivate.close();

            FileWriter fileWriterPublic=new FileWriter(publicKeyFile);
            fileWriterPublic.write(this.publicKey);
            fileWriterPublic.flush();
            fileWriterPublic.close();
        }
    }

    public static KeyPass genKeyPair(String seed, ReturnType returnType){
        try{
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.setSeed(seed.getBytes());
            //Modulus size must range from 512 to 1024 and be a multiple of 64
            keygen.initialize(KEY_SIZE, secureRandom);
            keygen.genKeyPair();
            KeyPair keys = keygen.genKeyPair();
            PrivateKey privateKey = keys.getPrivate();
            PublicKey publicKey = keys.getPublic();
            KeyPass keyPass=new KeyPass();
            if(returnType.equals(ReturnType.TYPE_BASE64)){
                keyPass.setPublicKey(UUtils.convertToBase64(publicKey.getEncoded()));
                keyPass.setPrivateKey(UUtils.convertToBase64(privateKey.getEncoded()));
            }else {
                keyPass.setPublicKey(UUtils.byteArrayToHexString(publicKey.getEncoded()));
                keyPass.setPrivateKey(UUtils.byteArrayToHexString(privateKey.getEncoded()));
            }
            return keyPass;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    //生成秘钥对
    public static void main(String args[]){
        try {
            KeyPass keyPass=genKeyPair("AKJSH71O)(*75S",ReturnType.TYPE_BASE64);
            System.out.println("pri:"+keyPass.getPrivateKey());
            System.out.println("pub:"+keyPass.getPublicKey());
        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
