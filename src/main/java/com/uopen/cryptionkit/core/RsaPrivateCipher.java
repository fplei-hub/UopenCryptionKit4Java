package com.uopen.cryptionkit.core;


import com.uopen.cryptionkit.UCipher;
import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.utils.StringUtils;
import com.uopen.cryptionkit.utils.UUtils;

import org.bouncycastle.util.encoders.Base64;
import javax.crypto.Cipher;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;


/**
 * RSA加解密工具（私钥持有方使用）
 *
 * @author fplei
 * @create 2020-05-30-17:45
 */
public class RsaPrivateCipher implements UCipher {

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
    public byte[] encode(String base64Key, byte[] content) throws Exception {
        if (StringUtils.isNull(base64Key) || content == null) {
            return null;
        }
        RSAPrivateKey rsaPrivateKey = KeyPairHelper.getPrivateKey(base64Key);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
        //该密钥能够加密的最大字节长度
        int splitLength = ((RSAPrivateKey) rsaPrivateKey).getModulus().bitLength() / 8 - 11;
        byte[][] arrays = UUtils.splitBytes(content, splitLength);
        StringBuffer stringBuffer = new StringBuffer();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            outputStream.write(cipher.doFinal(array));
        }
        return outputStream.toByteArray();
    }

    @Override
    public String encodeToBase64(String base64Key, String content) throws Exception {
        byte[] values = encode(base64Key, content.getBytes(Charset.forName("UTF-8")));
        if (values != null) {
            return new String(Base64.encode(values));
        }
        return null;
    }

    @Override
    public String encodeToHexString(String base64Key, String content) throws Exception {
        byte[] values = encode(base64Key, content.getBytes(Charset.forName("UTF-8")));
        if (values != null) {
            return UUtils.byteArrayToHexString(values);
        }
        return null;
    }

    @Override
    public byte[] decode(String base64Key, byte[] content) throws Exception {
        RSAPrivateKey rsaPrivateKey = KeyPairHelper.getPrivateKey(base64Key);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        //该密钥能够加密的最大字节长度
        int splitLength = ((RSAPrivateKey) rsaPrivateKey).getModulus().bitLength() / 8;
        byte[][] arrays = UUtils.splitBytes(content, splitLength);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            outputStream.write(cipher.doFinal(array));
        }
        return outputStream.toByteArray();
    }

    @Override
    public String decodeByBase64(String base64Key, String contentBase64) throws Exception {
        byte[] values = decode(base64Key, Base64.decode(contentBase64));
        if (values != null) {
            return new String(values, Charset.forName("UTF-8"));
        }
        return null;
    }

    @Override
    public String decodeByHexString(String base64Key, String contentHex) throws Exception {
        byte[] values = decode(base64Key, UUtils.hexStringToByteArray(contentHex));
        if (values != null) {
            return new String(values, Charset.forName("UTF-8"));
        }
        return null;
    }

    public static class KeyPairHelper {
        private static Map<String, Object> certMap = new java.util.concurrent.ConcurrentHashMap<String, Object>();
        /**
         * 用来指定保存密钥对的文件名和存储的名称
         */
        private static final String PUBLIC_KEY_NAME = "publicKey";
        private static final String PRIVATE_KEY_NAME = "privateKey";
        private static final String PUBLIC_FILENAME = "publicKey.properties";
        private static final String PRIVATE_FILENAME = "privateKey.properties";
        /**
         * 默认密钥大小
         */
        private static final int KEY_SIZE = 2048;
        /**
         * 密钥对生成器
         */
        private static KeyPairGenerator keyPairGenerator = null;
        private static KeyFactory keyFactory = null;
        /**
         * 缓存的密钥对
         */
        private static KeyPair keyPair = null;

        /** 初始化密钥工厂 */
        static {
            try {
                keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
                keyFactory = KeyFactory.getInstance(ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        /**
         * 生成密钥对
         * 将密钥分别用Base64编码保存到#publicKey.properties#和#privateKey.properties#文件中
         * 保存的默认名称分别为publicKey和privateKey
         */
        public static synchronized void generateKeyPair() {
            try {
                keyPairGenerator.initialize(KEY_SIZE, new SecureRandom(UUID.randomUUID().toString().getBytes()));
                keyPair = keyPairGenerator.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
            }
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            String publicKeyString = new String(Base64.encode(rsaPublicKey.getEncoded()), Charset.forName("UTF-8"));
            String privateKeyString = new String(Base64.encode(rsaPrivateKey.getEncoded()), Charset.forName("UTF-8"));
            storeKey(publicKeyString, PUBLIC_KEY_NAME, PUBLIC_FILENAME);
            storeKey(privateKeyString, PRIVATE_KEY_NAME, PRIVATE_FILENAME);
        }

        /**
         * 将指定的密钥字符串保存到文件中,如果找不到文件，就创建
         *
         * @param keyString 密钥的Base64编码字符串（值）
         * @param keyName   保存在文件中的名称（键）
         * @param fileName  目标文件名
         */
        private static void storeKey(String keyString, String keyName, String fileName) {
            Properties properties = new Properties();
            //存放密钥的绝对地址
            String path = null;
            try {
                path = RsaPrivateCipher.class.getClassLoader().getResource(fileName).toString();
                path = path.substring(path.indexOf(":") + 1);
            } catch (NullPointerException e) {
                //如果不存#fileName#就创建
                String classPath = RsaPrivateCipher.class.getClassLoader().getResource("").toString();
                String prefix = classPath.substring(classPath.indexOf(":") + 1);
                String suffix = fileName;
                File file = new File(prefix + suffix);
                try {
                    file.createNewFile();
                    path = file.getAbsolutePath();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
            try {
                OutputStream out = new FileOutputStream(path);
                properties.setProperty(keyName, keyString);
                properties.store(out, "There is " + keyName);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        /**
         * 获取密钥字符串
         *
         * @param keyName  需要获取的密钥名
         * @param fileName 密钥所在文件
         * @return Base64编码的密钥字符串
         */
        private static String getKeyString(String keyName, String fileName) throws Exception {
            if (RsaPrivateCipher.class.getClassLoader().getResource(fileName) == null) {
                generateKeyPair();
            }
            InputStream in = RsaPrivateCipher.class.getClassLoader().getResource(fileName).openStream();
            Properties properties = new Properties();
            properties.load(in);
            return properties.getProperty(keyName);
        }

        /**
         * 从文件获取RSA公钥
         *
         * @return RSA公钥
         */
        public static RSAPublicKey getPublicKey() throws Exception {
            String base64KeyPass = getKeyString(PUBLIC_KEY_NAME, PUBLIC_FILENAME);
            RSAPublicKey rsaPublicKey = (RSAPublicKey) certMap.get("PublicKey" + base64KeyPass.hashCode());
            if (rsaPublicKey != null) {
                return rsaPublicKey;
            }
            byte[] keyBytes = Base64.decode(base64KeyPass);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
            certMap.put("PublicKey" + base64KeyPass.hashCode(), rsaPublicKey);
            return rsaPublicKey;
        }

        /**
         * 公钥生产RSAPublicKey
         *
         * @param base64KeyPass base64密钥串
         * @return
         */
        public static RSAPublicKey getPublicKey(String base64KeyPass) throws Exception {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) certMap.get("PublicKey" + base64KeyPass.hashCode());
            if (rsaPublicKey != null) {
                return rsaPublicKey;
            }
            byte[] keyBytes = Base64.decode(base64KeyPass);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
            certMap.put("PublicKey" + base64KeyPass.hashCode(), rsaPublicKey);
            return rsaPublicKey;
        }

        /**
         * 从文件获取RSA私钥
         *
         * @return RSA私钥
         */
        public static RSAPrivateKey getPrivateKey() throws Exception {
            String base64PrivateKey = getKeyString(PRIVATE_KEY_NAME, PRIVATE_FILENAME);
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) certMap.get("PrivateKey" + base64PrivateKey.hashCode());
            if (rsaPrivateKey != null) {
                return rsaPrivateKey;
            }
            byte[] keyBytes = Base64.decode(base64PrivateKey);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            certMap.put("PrivateKey" + base64PrivateKey.hashCode(), rsaPrivateKey);
            return rsaPrivateKey;
        }

        /**
         * 生成私钥
         *
         * @param base64KeyPass base64密钥串
         * @return
         */
        public static RSAPrivateKey getPrivateKey(String base64KeyPass) throws Exception {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) certMap.get("PrivateKey" + base64KeyPass.hashCode());
            if (rsaPrivateKey != null) {
                return rsaPrivateKey;
            }
            byte[] keyBytes = Base64.decode(base64KeyPass);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            certMap.put("PrivateKey" + base64KeyPass.hashCode(), rsaPrivateKey);
            return rsaPrivateKey;
        }

        /**
         * 读取公钥，x509格式
         *
         * @param ins
         * @return
         * @throws Exception
         * @see
         */
        public static PublicKey getPublicKeyFromCert(InputStream ins) throws Exception {
            PublicKey pubKey = (PublicKey) certMap.get("PublicKey");
            if (pubKey != null) {
                return pubKey;
            }
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate cac = (Certificate) cf.generateCertificate(ins);
                pubKey = cac.getPublicKey();
                certMap.put("PublicKey", pubKey);
            } catch (Exception e) {
                if (ins != null)
                    ins.close();
                throw e;
            } finally {
                if (ins != null) {
                    ins.close();
                }
            }
            return pubKey;
        }

        /**
         * 读取PKCS12格式的key（私钥）pfx格式
         *
         * @param password
         * @return
         * @throws Exception
         * @see
         */
        public static PrivateKey getPrivateKeyFromPKCS12(String pfxFilePath,String password) throws Exception {
            PrivateKey priKey = (PrivateKey) certMap.get("PrivateKey");
            if (priKey != null) {
                return priKey;
            }
            KeyStore keystoreCA = KeyStore.getInstance("PKCS12");
            InputStream inputStream = new FileInputStream(pfxFilePath);
            try {
                // 读取CA根证书
                keystoreCA.load(inputStream, password.toCharArray());
                Enumeration<?> aliases = keystoreCA.aliases();
                String keyAlias = null;
                if (aliases != null) {
                    while (aliases.hasMoreElements()) {
                        keyAlias = (String) aliases.nextElement();
                        // 获取CA私钥
                        priKey = (PrivateKey) (keystoreCA.getKey(keyAlias, password.toCharArray()));
                        if (priKey != null) {
                            certMap.put("PrivateKey", priKey);
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                if (inputStream != null)
                    inputStream.close();
                throw e;
            } finally {
                if (inputStream != null) {
                    inputStream.close();
                }
            }
            return priKey;
        }

    }
}
