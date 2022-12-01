package com.uopen.cryptionkit;

import com.uopen.cryptionkit.core.AesCipher;
import com.uopen.cryptionkit.core.DesCipher;
import com.uopen.cryptionkit.core.DsaSignature;
import com.uopen.cryptionkit.core.HmacSHA1Cipher;
import com.uopen.cryptionkit.core.HmacSHA256Cipher;
import com.uopen.cryptionkit.core.Md5Signature;
import com.uopen.cryptionkit.core.RsaPrivateCipher;
import com.uopen.cryptionkit.core.RsaPublicCipher;
import com.uopen.cryptionkit.core.Sm2Cipher;
import com.uopen.cryptionkit.core.Sm3Signature;
import com.uopen.cryptionkit.core.Sm4Cipher;
import com.uopen.cryptionkit.core.TripleDesCipher;
import com.uopen.cryptionkit.key.KeyCreator;
import com.uopen.cryptionkit.key.KeyCreatorDefault;
import com.uopen.cryptionkit.utils.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;

/**
 * Uopen加解密管理器，支持DES,3DES,AES,RSA,SM4,SM2加密，HmacSha1,HmacSha256,MD5,SM3,DAS签名
 * @author fplei
 * @create 2020-05-30-17:45
 * @email:1553234169@qq.com
 */
public class UEncryptionManager {
    private static KeyCreator keyCreator;
    private UCipher cipher;
    private USignature signature;
    private static Map<String, Object> objectCache = new java.util.concurrent.ConcurrentHashMap<String, Object>();

    public enum EncryptionHelper {
        INSTANCE;
        private UEncryptionManager encryptionManager;

        EncryptionHelper() {
            Security.addProvider(new BouncyCastleProvider());
            encryptionManager = new UEncryptionManager();
        }

        public UEncryptionManager getEncryptionHelper() {
            return this.encryptionManager;
        }
    }

    public static UEncryptionManager getInstance() {
        return EncryptionHelper.INSTANCE.getEncryptionHelper();
    }

    /**
     * 注入Key
     * @param mKeyCreator
     */
    public static void initKey(KeyCreator mKeyCreator) {
        keyCreator = mKeyCreator;
    }

    public void checkKey() {
        if (keyCreator == null) {
            keyCreator = KeyCreatorDefault.DEFAULT();
        }
    }

    public UCipher getCipher(Class clazz) throws Exception {
        cipher = (UCipher) objectCache.get(clazz.getName());
        if (cipher == null) {
            Object tmp = clazz.newInstance();
            if (tmp instanceof UCipher) {
                cipher = (UCipher) tmp;
                objectCache.put(clazz.getName(), cipher);
            } else {
                throw new Exception("this class " + clazz.getName() + "not instance of " + UCipher.class.getName());
            }
        }
        return cipher;
    }

    public USignature getSignature(Class clazz) throws Exception {
        signature = (USignature) objectCache.get(clazz.getName());
        if (signature == null) {
            Object tmp = clazz.newInstance();
            if (tmp instanceof USignature) {
                signature = (USignature) clazz.newInstance();
                objectCache.put(clazz.getName(), signature);
            } else {
                throw new Exception("this class " + clazz.getName() + "not instance of " + USignature.class.getName());
            }
        }
        return signature;
    }
    /**
     * des加解密
     *
     * @param content        内容
     * @param type           操作类型
     * @param returnDataType 返回数据类型
     * @return
     */
    public String withOneDes(String content, Op type, ReturnType returnDataType){
        checkKey();
        if (StringUtils.isNull(keyCreator.getDesPass())) {
            throw new RuntimeException("Warning：we not found 'AesPass' in KeyCreator");
        }
        return optEncrypt(DesCipher.class, keyCreator.getDesPass(), content, type, returnDataType,null);
    }
    /**
     * Aes加解密
     *
     * @param content        内容
     * @param type           操作类型
     * @param returnDataType 返回数据类型
     * @return
     */
    public String withAes(String content, Op type, ReturnType returnDataType) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getAesPass())) {
           throw new RuntimeException("Warning：we not found 'AesPass' in KeyCreator");
        }
        return optEncrypt(AesCipher.class, keyCreator.getAesPass(), content, type, returnDataType,null);
    }

    /**
     *  Aes加解密 Pck5
     * @param content
     * @param type
     * @param returnDataType
     * @return
     */
    public String withAesPck5(String content, Op type, ReturnType returnDataType) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getAesPass())) {
            throw new RuntimeException("Warning：we not found 'AesPass' in KeyCreator");
        }
        HashMap<String,String> extendParam=new HashMap<>();
        extendParam.put(ExtendParamConstant.KeyName.MODE,ExtendParamConstant.KeyValue.MODE_ECB);
        extendParam.put(ExtendParamConstant.KeyName.PADDING,ExtendParamConstant.KeyValue.PADDING_PKCS5);
        return optEncrypt(AesCipher.class, keyCreator.getAesPass(), content, type, returnDataType,extendParam);
    }
    /**
     *  Aes加解密 Pck7
     * @param content
     * @param type
     * @param returnDataType
     * @return
     */
    public String withAesPck7(String content, Op type, ReturnType returnDataType) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getAesPass())) {
            throw new RuntimeException("Warning：we not found 'AesPass' in KeyCreator");
        }
        HashMap<String,String> extendParam=new HashMap<>();
        extendParam.put(ExtendParamConstant.KeyName.PADDING,ExtendParamConstant.KeyValue.PADDING_PKCS7);
        return optEncrypt(AesCipher.class, keyCreator.getAesPass(), content, type, returnDataType,extendParam);
    }
    /**
     * Aes加解密
     * @param content
     * @param type
     * @param returnDataType
     * @param extendParam
     * @return
     */
    public String withAes(String content, Op type, ReturnType returnDataType, HashMap<String,String> extendParam) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getAesPass())) {
            throw new RuntimeException("Warning：we not found 'AesPass' in KeyCreator");
        }
        return optEncrypt(AesCipher.class, keyCreator.getAesPass(), content, type, returnDataType,extendParam);
    }

    /**
     * 3des加解密
     *
     * @param content        内容
     * @param type           操作类型
     * @param returnDataType 返回数据类型
     * @return
     */
    public String withTripleDes(String content, Op type, ReturnType returnDataType) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getTriplePass())) {
            throw new RuntimeException("Warning：we not found 'TriplePass' in KeyCreator");
        }
        return optEncrypt(TripleDesCipher.class, keyCreator.getTriplePass(), content, type, returnDataType,null);
    }

    /**
     * MD5签名
     *
     * @param content        内容
     * @param returnDataType 返回数据类型
     * @return
     */
    public String withMd5(String content, ReturnType returnDataType) {
        return opSign(Md5Signature.class, content, returnDataType);
    }

    /**
     * HmacSh1签名
     *
     * @param content        内容
     * @param returnDataType 返回数据类型
     * @return
     */
    public String withHmacSha1(String content, ReturnType returnDataType) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getHmacShaPass())) {
            throw new RuntimeException("Warning：we not found 'HmacShaPass' in KeyCreator");
        }
        return optEncrypt(HmacSHA1Cipher.class, keyCreator.getHmacShaPass(), content, Op.Encryption, returnDataType,null);
    }

    /**
     * HmacSh256签名
     *
     * @param content        内容
     * @param returnDataType 返回数据类型
     * @return
     */
    public String withHmacSh256(String content, ReturnType returnDataType) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getHmacShaPass())) {
            throw new RuntimeException("Warning：we not found 'HmacShaPass' in KeyCreator");
        }
        return optEncrypt(HmacSHA256Cipher.class, keyCreator.getHmacShaPass(), content, Op.Encryption, returnDataType,null);
    }

    /**
     * RSA公钥加解密
     *
     * @param content        内容
     * @param operator       操作
     * @param returnDataType 加密返回的数据类型
     * @return 返回值类型根据 ReturnType 决定
     */
    public String withRsaPrivate(String content, Op operator, ReturnType returnDataType) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getRsaPrivatePass())) {
            throw new RuntimeException("Warning：we not found 'RsaPrivatePass' in KeyCreator");
        }
        return optEncrypt(RsaPrivateCipher.class, keyCreator.getRsaPrivatePass(), content, operator, returnDataType,null);
    }

    /**
     * RSA公钥加解密
     *
     * @param content        内容，解密值类型根据加密时传的ReturnType决定
     * @param operator       操作
     * @param returnDataType 加密时数据编码类型
     * @return
     */
    public String withRsaPublic(String content, Op operator, ReturnType returnDataType) {
        checkKey();
        if (StringUtils.isNull(keyCreator.getRsaPublicPass())) {
            throw new RuntimeException("Warning：we not found 'RsaPublicPass' in KeyCreator");
        }
        return optEncrypt(RsaPublicCipher.class, keyCreator.getRsaPublicPass(), content, operator, returnDataType,null);
    }

    /**
     * 杂凑SM3签名
     * @param content
     * @param returnDataType
     * @return
     */
    public String withSm3(String content, ReturnType returnDataType){
        return opSign(Sm3Signature.class, content, returnDataType);
    }

    /**
     * 国秘SM2非对称加解密(私钥操作)
     * @param content 内容
     * @param operator 操作(加密或解密)
     * @param returnDataType 操作数据类型（HEX,BASE64）
     * @return 返回操作数据局
     */
    public String withSm2PrivateKey(String content, Op operator, ReturnType returnDataType){
        checkKey();
        if (StringUtils.isNull(keyCreator.getSm2PrivatePass())) {
            throw new RuntimeException("Warning：we not found 'Sm2PrivatePass' in KeyCreator");
        }
        return optEncrypt(Sm2Cipher.class, keyCreator.getSm2PrivatePass(), content, operator, returnDataType,null);
    }
    /**
     * 国秘SM2非对称加解密（公钥操作）
     * @param content 内容
     * @param operator 操作(加密或解密)
     * @param returnDataType 操作数据类型（HEX,BASE64）
     * @return 返回操作数据局
     */
    public String withSm2PublicKey(String content, Op operator, ReturnType returnDataType){
        checkKey();
        if (StringUtils.isNull(keyCreator.getSm2PublicPass())) {
            throw new RuntimeException("Warning：we not found 'Sm2PrivatePass' in KeyCreator");
        }
        return optEncrypt(Sm2Cipher.class, keyCreator.getSm2PublicPass(), content, operator, returnDataType,null);
    }

    /**
     * 国秘SM4加解密
     * @param content 内容
     * @param operator 操作(加密或解密)
     * @param returnDataType 操作数据类型（HEX,BASE64）
     * @return 返回操作数据局
     */
    public String withSm4(String content, Op operator, ReturnType returnDataType){
        checkKey();
        if (StringUtils.isNull(keyCreator.getSm4Pass())) {
            throw new RuntimeException("Warning：we not found 'Sm4Pass' in KeyCreator");
        }
        return optEncrypt(Sm4Cipher.class, keyCreator.getSm4Pass(), content, operator, returnDataType,null);
    }

    /**
     * 加签
     * @param content
     * @param returnDataType
     * @return
     */
    public String withDasSign(String content,ReturnType returnDataType){
        checkKey();
        if (StringUtils.isNull(keyCreator.getDasPrivateKey())) {
            throw new RuntimeException("Warning：we not found 'DasPrivateKey' in KeyCreator");
        }
       return opSignByKey(DsaSignature.class,keyCreator.getDasPrivateKey(),content,returnDataType);
    }

    /**
     * 验签
     * @param data
     * @param sign
     * @param returnType
     * @return
     */
    public Boolean withDasVerify(String data,String sign,ReturnType returnType){
        checkKey();
        if (StringUtils.isNull(keyCreator.getDasPublicKey())) {
            throw new RuntimeException("Warning：we not found 'DasPublicKey' in KeyCreator");
        }
        return verify(DsaSignature.class,keyCreator.getDasPublicKey(),sign,data,returnType);
    }

    public String optEncrypt(Class clazz, String key, String content, Op type, ReturnType returnDataType,HashMap<String,String> extendParam) {
        String tempStr = null;
        try {
            cipher = getCipher(clazz);
            cipher.setReturnDataType(returnDataType);
            cipher.setExtendParams(extendParam);
            switch (type) {
                case Decrypt:
                    tempStr = cipher.decode(key, content);
                    break;
                case Encryption:
                    tempStr = cipher.encode(key, content);
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return tempStr;
    }

    public String opSign(Class clazz, String content, ReturnType returnDataType) {
        try {
            signature = getSignature(clazz);
            signature.setReturnDataType(returnDataType);
            return signature.signToString(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 加签
     * @param clazz
     * @param key
     * @param content
     * @param returnDataType
     * @return
     */
    public String opSignByKey(Class clazz,String key, String content, ReturnType returnDataType) {
        try {
            signature = getSignature(clazz);
            signature.setReturnDataType(returnDataType);
            return signature.signByKey(key,content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 签名验证
     * @param clazz
     * @param key
     * @param sign
     * @param content
     * @param returnDataType
     * @return
     */
    public Boolean verify(Class clazz,String key,String sign, String content, ReturnType returnDataType){
        try {
            signature = getSignature(clazz);
            signature.setReturnDataType(returnDataType);
            return signature.verify(key,content,sign);
        }catch (Exception e){
            e.printStackTrace();
        }
        return Boolean.FALSE;
    }



    public static KeyCreator getKeyCreator() {
        return keyCreator;
    }
}
