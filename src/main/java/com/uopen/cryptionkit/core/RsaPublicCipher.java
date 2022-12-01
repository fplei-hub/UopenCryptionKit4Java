package com.uopen.cryptionkit.core;


import com.uopen.cryptionkit.UCipher;
import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.utils.UUtils;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;


/**
 * RSA加解密（公钥持有者使用）
 * @author fplei
 * @create 2020-05-30-17:45
 * @email: 1553234169@qq.com
 */
public class RsaPublicCipher implements UCipher {
    /**
     * 算法名称
     */
    private static final String ALGORITHM = "RSA";
    private ReturnType returnType = ReturnType.TYPE_HEX;

    @Override
    public void setReturnDataType(ReturnType mReturnType) {
        this.returnType = mReturnType;
    }

    @Override
    public void setExtendParams(HashMap<String, String> extendParams) {
        
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
    public byte[] encode(String base64key, byte[] content) throws Exception {
        RSAPublicKey rsaPublicKey = RsaPrivateCipher.KeyPairHelper.getPublicKey(base64key);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        //该密钥能够加密的最大字节长度
        int splitLength = ((RSAPublicKey) rsaPublicKey).getModulus().bitLength() / 8 - 11;
        byte[][] arrays = UUtils.splitBytes(content, splitLength);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            byteArrayOutputStream.write(cipher.doFinal(array));
        }
        return byteArrayOutputStream.toByteArray();
    }

    @Override
    public String encodeToBase64(String base64key, String content) throws Exception {
        byte[] values = encode(base64key, content.getBytes(Charset.forName("UTF-8")));
        if (values != null) {
            return new String(Base64.encode(values), Charset.forName("UTF-8"));
        }
        return null;
    }

    @Override
    public String encodeToHexString(String base64key, String content) throws Exception {
        byte[] values = encode(base64key, content.getBytes(Charset.forName("UTF-8")));
        if (values != null) {
            return UUtils.byteArrayToHexString(values);
        }
        return null;
    }

    @Override
    public byte[] decode(String base64key, byte[] content) throws Exception {
        RSAPublicKey rsaPublicKey = RsaPrivateCipher.KeyPairHelper.getPublicKey(base64key);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
        //该密钥能够加密的最大字节长度
        int splitLength = ((RSAPublicKey) rsaPublicKey).getModulus().bitLength() / 8;
        byte[][] arrays = UUtils.splitBytes(content, splitLength);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            byteArrayOutputStream.write(cipher.doFinal(array));
        }
        return byteArrayOutputStream.toByteArray();
    }

    @Override
    public String decodeByBase64(String base64key, String contentBase64) throws Exception {
        byte[] values = decode(base64key, Base64.decode(contentBase64));
        if (values != null) {
            return new String(values, Charset.forName("UTF-8"));
        }
        return null;
    }

    @Override
    public String decodeByHexString(String base64key, String contentHex) throws Exception {
        byte[] values = decode(base64key, UUtils.hexStringToByteArray(contentHex));
        if (values != null) {
            return new String(values, Charset.forName("UTF-8"));
        }
        return null;
    }
}
