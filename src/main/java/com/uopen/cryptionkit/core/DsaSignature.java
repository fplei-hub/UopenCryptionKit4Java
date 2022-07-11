package com.uopen.cryptionkit.core;

import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.USignature;
import com.uopen.cryptionkit.utils.StringUtils;
import com.uopen.cryptionkit.utils.UUtils;

import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * DSA签名算法
 * @author fplei
 * @create 2020-05-30-17:45
 * @email:1553234169@qq.com
 */
public class DsaSignature implements USignature {
    private ReturnType returnType = ReturnType.TYPE_HEX;
    public static final String KEY_ALGORITHM = "DSA";
    public static final String SIGNATURE_ALGORITHM = "DSA";

    @Override
    public void setReturnDataType(ReturnType returnType) {
        this.returnType=returnType;
    }

    @Override
    public byte[] sign(byte[] content) {
        return null;
    }

    @Override
    public byte[] signByKey(byte[] privateKey, byte[] content) {
        if(content==null|| privateKey==null){
            return null;
        }
        try{
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
            PrivateKey priKey = factory.generatePrivate(keySpec);//生成 私钥
            // 用私钥对信息进行数字签名
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(priKey);
            signature.update(content);
            return signature.sign();
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String signByKey(String privateKey, String content) {
        if(StringUtils.isNull(privateKey)||StringUtils.isNull(content)){
            throw new RuntimeException("privateKey or content is null");
        }
        byte[] _keys=null;
        if (returnType==ReturnType.TYPE_BASE64){
            _keys= UUtils.convertBase64ToBytes(privateKey);
        }else {
            _keys= UUtils.hexStringToByteArray(privateKey);
        }
        try {
            byte[] _datas=content.getBytes("UTF-8");
            byte[] result=signByKey(_keys,_datas);
            switch (returnType) {
                case TYPE_STRING:
                    byte[] values = content.getBytes(Charset.forName("UTF-8"));
                    return new String(values);
                case TYPE_BASE64:
                    return UUtils.convertToBase64(result);
                case TYPE_HEX:
                    return UUtils.byteArrayToHexString(result);
                default:
                    return null;
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean verify(String publicKey, String data, String sign) {
        if(data==null||publicKey==null|| StringUtils.isNull(sign)){
            return false;
        }
        try{
            byte[] _keys=null;
            byte[] _data=data.getBytes("UTF-8");
            byte[] _signBytes=null;
            if (returnType==ReturnType.TYPE_BASE64){
                _keys= UUtils.convertBase64ToBytes(publicKey);
                _signBytes=UUtils.convertBase64ToBytes(sign);
            }else {
                _keys= UUtils.hexStringToByteArray(publicKey);
                _signBytes=UUtils.hexStringToByteArray(sign);
            }
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(_keys);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(pubKey);
            signature.update(_data);
            return signature.verify(_signBytes); //验证签名
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public String signToString(String content) {
        return null;
    }

    @Override
    public String signToBase64(String content) {
        return null;
    }

    @Override
    public String signToHexString(String content, boolean isUpper) {
        return null;
    }


}
