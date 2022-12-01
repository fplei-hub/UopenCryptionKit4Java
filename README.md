# UopenCryptionKit4Java
UopenCryptionKit4Java加解密库集合了常见的加解密以及签名算法工具，将常见的加密器，加签器统一封装提供操作，分离密码与加密过程。

####库中支持加密器类型：<br/>
1.AES <br/>
2.DES <br/> 
3.3DES <br/> 
4.Sm2  <br/> 
5.Sm4  <br/>
6.RSA  <br/>

####库中支持签名器类型：<br/>
1.DSA <br/>
2.HmacSHA1 <br/> 
3.HmacSHA256 <br/> 
4.Md5  <br/> 
5.SM3  <br/>

####项目结构<br/>
com.uopen.cryptionkit <br/>
|---core 该包下包含所有分装好的加密器 <br/>
|---key 该包主要存放密码接口，对接具体业务秘钥<br/>
|---utils 工具包<br/>
|---Op.java 列举操作类型<br/>
|---ReturnType.java 加解密操作数据类型<br/>
|---UEncryptionManager.java 加解密操作入口

####使用说明<br/>  
Step1.Maven or Gradle引用  
Maven：
~~~C 
<dependency>
  <groupId>io.github.fpleihub</groupId>
  <artifactId>UopenCryptionKit4Java</artifactId>
  <version>1.0</version>
</dependency>
~~~
Gradle：
~~~C 
implementation 'io.github.fpleihub:UopenCryptionKit4Java:1.0'
~~~
Step2.具体业务项目通过继承KeyCreator实现为项目 UopenCryptionKit 提供操作秘钥，需要使用到哪些加密器则对应的需要提供对应秘钥，如:<br/>
~~~C 
public class MyEncryptKeySource extends KeyCreator {
    @Override
    public String getAesPass() {
        return "my2020aes!@#_121872";
    }

    @Override
    public String getTriplePass() {
        return "my2020des$#_!1234567890";
    }

    @Override
    public String getRsaPrivatePass() {
        return "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCFKHC4jBwPDyGzCYGsqUaGcNCc139qIbmNrkGMaqnKOKF3h3sbx1iqz3gqlYLh+XWoyWW3C5RTykTdnUCe4farGXE2Vo4BtP1AdnzqMdrojLmuAaH2isDMZcmzr/vWNRQDu0kJ2T14txZ2Hu9nNhf87YQGaxjd7jUVmqbAhcxkkSffRGcjXfIhrBLPdEm6FvXD6vUS8H4W2tobQLIZOZo1h1uc9DmnpVsZWk9kU/ndmwcw7ofvlU/A9pEF2zadk2yxI6PbCjy93sAYJuoZaAaIq7hP+mkCEW6z+eiMDkc7AyLrhCJpM2tnwfEOfHWUPRVsolLvPguQNw0QF5rI52wlAgMBAAECggEASu28sDw3Ncof/m0lCRGf29rzqK4ixof/r9gUjn0e2eoQAgC8p57/J+7jAaNsKNiE+tuJXv0nFBdHtSTdzgn9Eb6ZVChUdGVx9Ko4FFjFhAJcIaxNhTwCzYGhhHlMzvbDMm5a5S3XR2xPOVyi/oMT8IF+v1XYglmeiW+i0cb4gsXTrTeytgNJOIj5DzZhq4VM2Wedi/259n0MykE3miE9NW4io2Ozk4lA8dxhjCJgSpDg3gi2CF9eVCVePBTK2PbS5OMNd1FwW7ns9Ac2Au9jhQTrcSFzGbd0VXuyyjkYizeyWvSSFbZpcG/a4vtn1NwhbD/Z59owFt50OUmjXslB6QKBgQC/PheurpUxzlTodMFzaVtoaWsSLbT+texcNYg0dlKYF9jP5buRJK4QynFTYfopIaMNNOWlohzNx0jDpjR1L8qy/E9ZC+TN3Bu7emNtAdWfWtxQV3x/29vyQJdeiUtD92QYN6orVG8om/G8qhg33HftcOFl4N/mYOMldtYPrvK29wKBgQCyP0WSnIhymzbxw200Z8JBYKIE/w+cnbUBNqJjmF9s6v9OaLF3fmuXCQZPixdS4vk3UOTwWGa7WIUe39Fbose2gFJheoFi9i7AC5+gghdV5BlY2d9Nfe+Gt9S3UEZYsBefvRdrs5d9/XAwtQoaXkpeFdF11u4JE7y7duUhI4DiwwKBgEhGbyzVTg1ErVIsze+QIbuUG6MDIyQgHPO8R32MOirA2G+5oul3s1ElMS8SGDjzPWwAUcoHOluKtTU72xduuGxsbpB4rkAer1xrJKhNyS4waJL0fVjU/orPXmWb/ZXyKSH955H4lwoB5Zonrn9uEuTphEW8duHaO/4sqznCJHiBAoGAYx92dCKiaoFQW7/e0d7Fkw/G6dphdynoh4U3ZwVMQ8inM5Za4mWmNTaqkL97t/dKue09cz7l2ldOqC21Qi1SvHW92kGDBGJ8+wU7vsm5amVPhy6Z1IEtG5DNNSfqBtXePVGtXZJgs4qlwiBbPvCikJG3ir18YAXe1a03nGce/HsCgYEArK2zX+t25C4n+AACXJNh85uTCALxlJfqrzopdjaAVYPXJHPFvhGaqLL91T5j1MXKdBOWOBlrg4ZBTPv1/fsPUI0mqmxBnM04aBd7r1QVWVqI132r33zLLZU0d7iByEruMxNSNp9MzGJm8F8PJxGccGksoNyb3ENgdRxg3pyNgNU\\=";
    }

    @Override
    public String getRsaPublicPass() {
        return "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhShwuIwcDw8hswmBrKlGhnDQnNd/aiG5ja5BjGqpyjihd4d7G8dYqs94KpWC4fl1qMlltwuUU8pE3Z1AnuH2qxlxNlaOAbT9QHZ86jHa6Iy5rgGh9orAzGXJs6/71jUUA7tJCdk9eLcWdh7vZzYX/O2EBmsY3e41FZqmwIXMZJEn30RnI13yIawSz3RJuhb1w+r1EvB+FtraG0CyGTmaNYdbnPQ5p6VbGVpPZFP53ZsHMO6H75VPwPaRBds2nZNssSOj2wo8vd7AGCbqGWgGiKu4T/ppAhFus/nojA5HOwMi64QiaTNrZ8HxDnx1lD0VbKJS7z4LkDcNEBeayOdsJQIDAQAB";
    }

    @Override
    public String getHmacShaPass() {
        return "bilibili1219832020";
    }

    @Override
    public String getSm2PublicPass() {
        return "0475658556b7ebff57a95b4da1cfefdb131f22909e2cd3265ace57d67a8033d522d40173db64a78a21d68035148694e01ffd973fb1c1af471c016e59c60c01fc0c";
    }

    @Override
    public String getSm2PrivatePass() {
        return "1eadfb948c582c03819d130837de5a6dcb9d8f6101ea1cf05982c27fb75027a5";
    }

    @Override
    public String getSm4Pass() {
        return "JeF8U9wHFOMfs2Y8";
    }

    @Override
    public String getDasPrivateKey() {
        return "MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUBiCZo7Aw+lPTaXf8an2bdqMVCMo=";
    }

    @Override
    public String getDasPublicKey() {
        return "MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGASIyEgiooFat7lb8fIuTir5JyvxDHBZIbwcvFewZ2eb8Fv7VW+z84CsjNswNOu1f81palcFA8vDyp2bv2tP+3OAAEnWbjYJQDNTc29ZZk3r0SwnPlmlFqLXUmBF8ROce991WEI0khGLwTNlNSMynhLljFZnW1fGplKzWMFetL7DQ=";
    }
}
~~~
密码管理器有几个地方需要注意  
1）3DES秘钥，长度最好固定24个字符，否则不足将会自动追加补0,或超出会自动截断到24个字符  
2）RSA秘钥对可通过/utils/RsaKeyHelper.java生成，内置默认使用Base64字符串作为秘钥串，如果需要更换层数据类型(ReturnType中类型列表)，并且调整{RsaPrivateCipher.java/RsaPublicCipher.java}加密器的秘钥编码方式 <br/>
3）国秘SM2秘钥对可通过/utils/SM2KeyHelper.java}生成，内置默认使用十六进制字符串作为铭文秘钥，如果需要更换成其他的数据类型(ReturnType中类型列表)，并且调整{Sm2Cipher.java}加密器的秘钥编码方式。<br/>
4）国秘SM4秘钥长度为16个字符.  

Step3.将密码管理器初始化到UopenCryptionKit4中(可以使用时初始化，也可以项目启动是初始化)  
~~~C
UEncryptionManager.initKey(new MyEncryptKeySource());
~~~

Step4.使用UEncryptionManager进行加解密操作  
Op操作符 
~~~C 
//加密操作符
Encryption
//解密操作符
Decrypt
~~~
ReturnType  数据类型
~~~C 
/**
* 返回或解密传入数据普通字符串类型
*/
TYPE_STRING,
/**
* 返回或解密传入数据普通字Base64类型
*/
TYPE_BASE64,
/**
* 返回或解密传入数据普通字16进制类型
*/
TYPE_HEX
~~~
DEMO.1 AES加解密操作 
~~~C 
/**
* Aes加解密
* @param content        内容
* @param type           操作类型
* @param returnDataType 返回数据类型（加解密需要统一，内部会对数据做编码）
*/
String value = UEncryptionManager.getInstance().withAes("10---323_哈哈四大时刻18211！@", Op.Encryption, ReturnType.TYPE_HEX);
System.out.println("AES加密后值：" + value);

String value1 = UEncryptionManager.getInstance().withAes(value, Op.Decrypt, ReturnType.TYPE_HEX);
System.out.println("AES解密后值：" + value1);
~~~
DEMO.2 3DES加解密操作
~~~C   
String triple1 = UEncryptionManager.getInstance().withTripleDes("测试3des加解密字符串@(*!*@&!__", Op.Encryption, ReturnType.TYPE_BASE64);
System.out.println("3DES加密：" + triple1);

String triple2 = UEncryptionManager.getInstance().withTripleDes(triple1, Op.Decrypt, ReturnType.TYPE_BASE64);
System.out.println("3DES解密：" + triple2);
~~~

DEMO.3 RSA加解密操作  
RSA秘钥可通过RsaKeyHelper进行生成秘钥对，将生成好的秘钥放入秘钥管理器中，加解密器内部默认使用Base64，需要同时修改2个类  
1 修改RsaPrivateCipher.KeyPairHelper中generateKeyPair方法编码转换部分  
~~~C
public static synchronized void generateKeyPair() {
            try {
                //KEY_SIZE=2048
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
~~~
2 修改RsaPrivateCipher 中静态类 KeyPairHelper 中方法"getPublicKey"与"getPrivateKey"中秘钥编码类型  
~~~C 
//私钥 
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
//公钥
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
~~~
使用  
~~~C 
//公钥加密--》私钥解密
String rsaPublic = UEncryptionManager.getInstance().withRsaPublic("测试RSA公钥加解密!@823144aas_*!.>", Op.Encryption, ReturnType.TYPE_BASE64);
System.out.println("RSA公钥加密：" + rsaPublic);

String rsaPublic1 = UEncryptionManager.getInstance().withRsaPrivate(rsaPublic, Op.Decrypt, ReturnType.TYPE_BASE64);
System.out.println("RSA私钥解密：" + rsaPublic1);

//私钥加密---》公钥解密
String rsaPrivate = UEncryptionManager.getInstance().withRsaPrivate("测试RSA私钥主导加解密@!@!@!&@*!.>", Op.Encryption, ReturnType.TYPE_HEX);
System.out.println("RSA私钥加密：" + rsaPrivate);

String rsaPrivate1 = UEncryptionManager.getInstance().withRsaPublic(rsaPrivate, Op.Decrypt, ReturnType.TYPE_HEX);
System.out.println("RSA公钥解密：" + rsaPrivate1);
~~~

DEMO4. 国秘SM4加解密操作
~~~C   
//SM4加解密-秘钥为16字符长度
String sm4Encry= UEncryptionManager.getInstance().withSm4("测试Sm4对称加密算法——_90a8^$",Op.Encryption,ReturnType.TYPE_BASE64);
System.out.println("国秘SM4加密：" + sm4Encry);

String sm4Decry= UEncryptionManager.getInstance().withSm4(sm4Encry,Op.Decrypt,ReturnType.TYPE_BASE64);
System.out.println("国秘SM4解密：" + sm4Decry);
~~~

DEMO5. 国密SM2加解密操作
~~~C   
//客户端公钥加密--》服务端私钥解密
String sm2PublicKeyEncry= UEncryptionManager.getInstance().withSm2PublicKey("这是测试Sm2公钥加密私钥解密的内容）*（*&*&",Op.Encryption,ReturnType.TYPE_HEX);
System.out.println("SM2公钥加密：" + sm2PublicKeyEncry);

String sm2PrivateKeyDecry= UEncryptionManager.getInstance().withSm2PrivateKey(sm2PublicKeyEncry,Op.Decrypt,ReturnType.TYPE_HEX);
System.out.println("SM2私钥解密：" + sm2PrivateKeyDecry);
~~~

DEMO6.DSA加签与验证  
用于数据签名和验证，校验数据是否完整，或者被篡改，使用说明：  
1 生成加签和验证的公私钥 （详细见：DSAKeyHelper） 
2 客户端通过公钥进行加签  
3 服务端通过私钥进行签名验证
~~~C 
String dasResult= UEncryptionManager.getInstance().withDasSign("等待Das加签的数据",ReturnType.TYPE_BASE64);
System.out.println("DSA加签：" + dasResult);

Boolean dasFlag= UEncryptionManager.getInstance().withDasVerify("等待Das加签的数据",dasResult,ReturnType.TYPE_BASE64);
System.out.println("DSA公钥签名验证：" + dasFlag);
~~~

DEMO7.国密SM3杂凑签名
~~~C 
//SM3签名
String sm3Sign= UEncryptionManager.getInstance().withSm3("测试Sm3签名算法",ReturnType.TYPE_HEX);
System.out.println("国秘SM3签名：" + sm3Sign);
~~~

DEMO8.HMacSHA1/HMacSHA256 签名
~~~C 
String sign256Base64 = UEncryptionManager.getInstance().withHmacSh256("测试字符串asa@!_a", ReturnType.TYPE_HEX);
System.out.println("HmacSh256 指纹：" + sign256Base64);

String sign1Base64 = UEncryptionManager.getInstance().withHmacSha1("测试字符串asa@!_a", ReturnType.TYPE_HEX);
System.out.println("HmacSha1 指纹：" + sign1Base64);
~~~

DEMO9.MD5 指纹
~~~C 
String md5 = UEncryptionManager.getInstance().withMd5("哈哈杀死a123456", ReturnType.TYPE_BASE64);
System.out.println("md5 指纹：" + md5);
~~~
