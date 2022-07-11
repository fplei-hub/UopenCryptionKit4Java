package com.uopen.cryptionkit.core;


import com.uopen.cryptionkit.UCipher;
import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.utils.UUtils;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

/**
 * 3des加解密
 *
 * @author fplei
 * @create 2020-05-30-17:55
 * @email: 1553234169@qq.com
 */
public class TripleDesCipher implements UCipher {
    //定义加密算法，有DES、DESede(即3DES)、Blowfish
    private static final String Algorithm = "DESede";
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
    public byte[] encode(String key, byte[] content) throws Exception {
        if (key == null || content == null) {
            return null;
        }
        SecretKey deskey = new SecretKeySpec(build3DesKey(key), Algorithm);    //生成密钥
        Cipher c1 = Cipher.getInstance(Algorithm);    //实例化负责加密/解密的Cipher工具类
        c1.init(Cipher.ENCRYPT_MODE, deskey);    //初始化为加密模式
        return c1.doFinal(content);
    }

    @Override
    public String encodeToBase64(String key, String content) throws Exception {
        byte[] contents = content.getBytes(Charset.forName("UTF-8"));
        contents = encode(key, contents);
        return new String(Base64.encode(contents));
    }

    @Override
    public String encodeToHexString(String key, String content) throws Exception {
        byte[] contents = content.getBytes(Charset.forName("UTF-8"));
        contents = encode(key, contents);
        return UUtils.byteArrayToHexString(contents);
    }

    @Override
    public byte[] decode(String key, byte[] content) throws Exception {
        if (key == null || content == null) {
            return null;
        }
        SecretKey deskey = new SecretKeySpec(build3DesKey(key), Algorithm);
        Cipher c1 = Cipher.getInstance(Algorithm);
        c1.init(Cipher.DECRYPT_MODE, deskey);    //初始化为解密模式
        return c1.doFinal(content);
    }

    @Override
    public String decodeByBase64(String key, String contentBase64) throws Exception {
        byte[] contents = decode(key, Base64.decode(contentBase64));
        if (contents != null) {
            return new String(contents);
        }
        return null;
    }

    @Override
    public String decodeByHexString(String key, String contentHex) throws Exception {
        byte[] contents = decode(key, UUtils.hexStringToByteArray(contentHex));
        return new String(contents);
    }

    /*
     * 根据字符串生成密钥字节数组
     * @param keyStr 密钥字符串
     * @return
     * @throws UnsupportedEncodingException
     */
    private static byte[] build3DesKey(String keyStr) throws UnsupportedEncodingException {
        byte[] key = new byte[24];    //声明一个24位的字节数组，默认里面都是0
        byte[] temp = keyStr.getBytes("UTF-8");    //将字符串转成字节数组
        /*
         * 执行数组拷贝
         * System.arraycopy(源数组，从源数组哪里开始拷贝，目标数组，拷贝多少位)
         */
        if (temp.length <= key.length) {
            //如果temp不够24位，则拷贝temp数组整个长度的内容到key数组中
            System.arraycopy(temp, 0, key, 0, temp.length);
        } else {
            //如果temp大于24位，则拷贝temp数组24个长度的内容到key数组中
            System.arraycopy(temp, 0, key, 0, key.length);
        }
        return key;
    }
}
