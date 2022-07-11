package com.uopen.cryptionkit.core;


import com.uopen.cryptionkit.USignature;
import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.utils.UUtils;

import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5工具
 * @author fplei
 * @create 2020-05-30-17:45
 * @email:1553234169@qq.com
 */
public class Md5Signature implements USignature {
    private static final String Algorithm = "MD5";
    private ReturnType returnType = ReturnType.TYPE_HEX;

    @Override
    public void setReturnDataType(ReturnType mReturnType) {
        this.returnType = mReturnType;
    }

    @Override
    public byte[] sign(byte[] content) {
        if (content == null) {
            return null;
        }
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance(Algorithm);
            byte[] bytes = md5.digest(content);
            return bytes;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String signToBase64(String content) {
        byte[] values = content.getBytes(Charset.forName("UTF-8"));
        return new String(Base64.encode(sign(values)));
    }

    @Override
    public String signToHexString(String content, boolean isUpper) {
        byte[] values = content.getBytes(Charset.forName("UTF-8"));
        String after = UUtils.byteArrayToHexString(sign(values));
        if (isUpper) {
            after = after.toUpperCase();
        }
        return after;
    }

    @Override
    public String signToString(String content) {
        switch (returnType) {
            case TYPE_STRING:
                byte[] values = content.getBytes(Charset.forName("UTF-8"));
                return new String(values);
            case TYPE_BASE64:
                return signToBase64(content);
            case TYPE_HEX:
                return signToHexString(content, false);
            default:
                return null;
        }
    }

    @Override
    public byte[] signByKey(byte[] privateKey, byte[] content) {
        return new byte[0];
    }

    @Override
    public String signByKey(String privateKey, String content) {
        return null;
    }

    @Override
    public boolean verify(String publicKey, String data, String sign) {
        return false;
    }
}
