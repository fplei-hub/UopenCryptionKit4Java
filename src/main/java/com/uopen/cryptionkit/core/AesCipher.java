package com.uopen.cryptionkit.core;


import com.uopen.cryptionkit.ExtendParamConstant;
import com.uopen.cryptionkit.UCipher;
import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.utils.UUtils;
import org.bouncycastle.util.encoders.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 * AES加解密
 *
 * @author fplei
 * @create 2020-05-30-17:45
 */
public class AesCipher implements UCipher {
    private ReturnType returnType = ReturnType.TYPE_HEX;
    private HashMap<String,String> extendParams;
    private static final String defaultMode="ECB";
    private static final String defaultPadding="PKCS7Padding";
    private static final String defaultIv="0123456789";
    @Override
    public void setReturnDataType(ReturnType mReturnType) {
        this.returnType = mReturnType;
    }

    @Override
    public void setExtendParams(HashMap<String, String> extendParams) {
        this.extendParams=extendParams;
    }

    /**
     * get extend input mode
     * @return
     */
    private String getCustomMode(){
        if(extendParams==null){
            return defaultMode;
        }
        String _mode=extendParams.get(ExtendParamConstant.KeyName.MODE);
        if(_mode==null||_mode.length()<=0){
            return defaultMode;
        }
        return _mode;
    }
    /**
     * get extend input padding
     * @return
     */
    private String getCustomPadding(){
        if(extendParams==null){
            return defaultPadding;
        }
        String _padding=extendParams.get(ExtendParamConstant.KeyName.PADDING);
        if(_padding==null||_padding.length()<=0){
            return defaultPadding;
        }
        return _padding;
    }

    /**
     * 获取IV
     * @return
     */
    private String getCustomIv(){
        if(extendParams==null){
            return defaultIv;
        }
        String _iv=extendParams.get(ExtendParamConstant.KeyName.IV);
        if(_iv==null||_iv.length()<=0){
            return defaultIv;
        }
        return _iv;
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
        String _iv=getCustomIv();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(_iv.getBytes());
        byte[] raw = key.getBytes("UTF-8");
        SecretKey _key = new SecretKeySpec(raw, "AES");
        String _mode=getCustomMode();
        String alt="AES/"+_mode+"/"+getCustomPadding();
        Cipher cipher = Cipher.getInstance(alt);
        if(_mode.equals(defaultMode)){
            cipher.init(Cipher.ENCRYPT_MODE, _key);
        }else {
            cipher.init(Cipher.ENCRYPT_MODE, _key,ivParameterSpec);
        }
        byte[] byte_AES = cipher.doFinal(content);
        return byte_AES;
    }

    @Override
    public byte[] decode(String key, byte[] content) throws Exception {
        String _iv=getCustomIv();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(_iv.getBytes());
        byte[] raw = key.getBytes("UTF-8");
        SecretKey _key = new SecretKeySpec(raw, "AES");
        String _mode=getCustomMode();
        String alt="AES/"+_mode+"/"+getCustomPadding();
        Cipher cipher = Cipher.getInstance(alt);
        if(_mode.equals(defaultMode)){
            cipher.init(Cipher.DECRYPT_MODE, _key);
        }else {
            cipher.init(Cipher.DECRYPT_MODE, _key,ivParameterSpec);
        }
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
