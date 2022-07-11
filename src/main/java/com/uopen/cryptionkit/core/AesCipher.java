package com.uopen.cryptionkit.core;


import com.uopen.cryptionkit.UCipher;
import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.utils.UUtils;
import org.bouncycastle.util.encoders.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.SecureRandom;

/**
 * AES加解密
 *
 * @author fplei
 * @create 2020-05-30-17:45
 */
public class AesCipher implements UCipher {
    private ReturnType returnType = ReturnType.TYPE_HEX;

    @Override
    public void setReturnDataType(ReturnType mReturnType) {
        this.returnType = mReturnType;
    }

    @Override
    public String encode(String key, String content) throws Exception {
        switch (returnType) {
            case TYPE_HEX:
                return encodeToHexString(key, content);
            case TYPE_BASE64:
                return encodeToBase64(key, content);
            case TYPE_STRING:
                byte[] values = encode(key, content.getBytes(Charset.forName("UTF-8")));
                return new String(values);
            default:
                return null;
        }
    }

    @Override
    public String decode(String key, String content) throws Exception {
        switch (returnType) {
            case TYPE_HEX:
                return decodeByHexString(key, content);
            case TYPE_BASE64:
                return decodeByBase64(key, content);
            case TYPE_STRING:
                byte[] values = decode(key, content.getBytes(Charset.forName("UTF-8")));
                return new String(values);
            default:
                return null;
        }
    }

    @Override
    public String encodeToBase64(String key, String content) throws Exception {
        byte[] values = encode(key, content.getBytes(Charset.forName("UTF-8")));
        if (values != null) {
            return new String(Base64.encode(values), Charset.forName("UTF-8"));
        }
        return null;
    }

    @Override
    public String encodeToHexString(String key, String content) throws Exception {
        byte[] values = encode(key, content.getBytes(Charset.forName("UTF-8")));
        if (values != null) {
            return UUtils.byteArrayToHexString(values);
        }
        return null;
    }

    @Override
    public byte[] encode(String key, byte[] content) throws Exception {
        //1.构造密钥生成器，指定为AES算法,不区分大小写
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        //2.根据ecnodeRules规则初始化密钥生成器
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(key.getBytes());
        //生成一个128位的随机源,根据传入的字节数组
        keygen.init(128, random);
        //3.产生原始对称密钥
        SecretKey original_key = keygen.generateKey();
        //4.获得原始对称密钥的字节数组
        byte[] raw = original_key.getEncoded();
        //5.根据字节数组生成AES密钥
        SecretKey _key = new SecretKeySpec(raw, "AES");
        //6.根据指定算法AES自成密码器
        Cipher cipher = Cipher.getInstance("AES");
        //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY
        cipher.init(Cipher.ENCRYPT_MODE, _key);
        //8.根据密码器的初始化方式--加密：将数据加密
        byte[] byte_AES = cipher.doFinal(content);
        return byte_AES;
    }

    @Override
    public byte[] decode(String key, byte[] content) throws Exception {
        //1.构造密钥生成器，指定为AES算法,不区分大小写
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        //2.根据ecnodeRules规则初始化密钥生成器
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(key.getBytes());
        //生成一个128位的随机源,根据传入的字节数组
        keygen.init(128, random);
        //3.产生原始对称密钥
        SecretKey original_key = keygen.generateKey();
        //4.获得原始对称密钥的字节数组
        byte[] raw = original_key.getEncoded();
        //5.根据字节数组生成AES密钥
        SecretKey _key = new SecretKeySpec(raw, "AES");
        //6.根据指定算法AES自成密码器
        Cipher cipher = Cipher.getInstance("AES");
        //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密(Decrypt_mode)操作，第二个参数为使用的KEY
        cipher.init(Cipher.DECRYPT_MODE, _key);
        byte[] byte_decode = cipher.doFinal(content);
        return byte_decode;
    }

    @Override
    public String decodeByBase64(String key, String contentBase64) throws Exception {
        byte[] values = decode(key, Base64.decode(contentBase64));
        if (values != null) {
            return new String(values, Charset.forName("UTF-8"));
        }
        return null;
    }

    @Override
    public String decodeByHexString(String key, String contentHex) throws Exception {
        byte[] values = decode(key, UUtils.hexStringToByteArray(contentHex));
        if (values != null) {
            return new String(values, Charset.forName("UTF-8"));
        }
        return null;
    }


}
