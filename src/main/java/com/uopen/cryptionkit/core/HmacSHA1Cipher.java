package com.uopen.cryptionkit.core;


import com.uopen.cryptionkit.UCipher;
import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.utils.UUtils;

import org.bouncycastle.util.encoders.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;

/**
 * SHA1签名加密(只能加签，不能逆向解密)
 *
 * @author fplei
 * @create 2020-05-30-17:45
 * @email：1553234169@qq.com
 */
public class HmacSHA1Cipher implements UCipher {
    private static final String Algorithm = "HmacSHA1";
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
        if (content == null || key == null) {
            return null;
        }
        SecretKey signingKey = new SecretKeySpec(key.getBytes(), Algorithm);
        Mac mac = Mac.getInstance(Algorithm);
        mac.init(signingKey);
        return mac.doFinal(content);
    }

    @Override
    public String encodeToBase64(String key, String content) throws Exception {
        byte[] values = encode(key, content.getBytes(Charset.forName("UTF-8")));
        return new String(Base64.encode(values));
    }

    @Override
    public String encodeToHexString(String key, String content) throws Exception {
        byte[] values = encode(key, content.getBytes(Charset.forName("UTF-8")));
        return UUtils.byteArrayToHexString(values);
    }

    @Override
    public byte[] decode(String key, byte[] content) {
        return new byte[0];
    }

    @Override
    public String decodeByBase64(String key, String contentBase64) {
        return null;
    }

    @Override
    public String decodeByHexString(String key, String contentHex) {
        return null;
    }
}
