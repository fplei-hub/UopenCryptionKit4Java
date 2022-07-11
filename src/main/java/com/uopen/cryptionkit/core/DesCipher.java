package com.uopen.cryptionkit.core;

import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.UCipher;
import com.uopen.cryptionkit.utils.UUtils;
import org.bouncycastle.util.encoders.Base64;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * des加解密
 * @author fplei
 * @create 2020-05-30-17:55
 * @email: 1553234169@qq.com
 */
public class DesCipher implements UCipher {
    private static final String ALGORITHM_DES = "DES/CBC/PKCS5Padding";
    private static final String Algorithm = "DES";
    private static final String IV="12345678";
    private ReturnType returnType = ReturnType.TYPE_HEX;
    @Override
    public void setReturnDataType(ReturnType returnType) {
        this.returnType = returnType;
    }

    @Override
    public byte[] encode(String key, byte[] content) throws Exception {
        if(content==null||key==null){
            return null;
        }
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(Algorithm);
            DESKeySpec dks = new DESKeySpec(key.getBytes("UTF-8"));
            // key的长度不能够小于8位字节
            Key secretKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
            AlgorithmParameterSpec paramSpec = iv;
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            return cipher.doFinal(content);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
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
        if(content==null||key==null){
            return null;
        }
        try{
            DESKeySpec dks = new DESKeySpec(key.getBytes("UTF-8"));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(Algorithm);
            // key的长度不能够小于8位字节
            Key secretKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
            IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
            AlgorithmParameterSpec paramSpec = iv;
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
            return cipher.doFinal(content);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
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
}
