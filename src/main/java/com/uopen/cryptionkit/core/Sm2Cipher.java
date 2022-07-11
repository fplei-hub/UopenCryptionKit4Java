package com.uopen.cryptionkit.core;

import com.uopen.cryptionkit.ReturnType;
import com.uopen.cryptionkit.UCipher;
import com.uopen.cryptionkit.utils.UUtils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;

/**
 * SM2国秘非对称，类似RSA，比其效率高，更安全
 * @author fplei
 * @create 2020-05-30-17:45
 * @email: 1553234169@qq.com
 */
public class Sm2Cipher implements UCipher {
    private ReturnType returnType = ReturnType.TYPE_HEX;
    //正式参数
    public static String[] ecc_param = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    };
    public final BigInteger ecc_p;
    public final BigInteger ecc_a;
    public final BigInteger ecc_b;
    public final BigInteger ecc_n;
    public final BigInteger ecc_gx;
    public final BigInteger ecc_gy;
    public final ECCurve ecc_curve;
    public final ECPoint ecc_point_g;
    public final ECDomainParameters ecc_bc_spec;
    public final ECKeyPairGenerator ecc_key_pair_generator;
    public final ECFieldElement ecc_gx_fieldelement;
    public final ECFieldElement ecc_gy_fieldelement;
    public Sm2Cipher(){
        this.ecc_p = new BigInteger(ecc_param[0], 16);
        this.ecc_a = new BigInteger(ecc_param[1], 16);
        this.ecc_b = new BigInteger(ecc_param[2], 16);
        this.ecc_n = new BigInteger(ecc_param[3], 16);
        this.ecc_gx = new BigInteger(ecc_param[4], 16);
        this.ecc_gy = new BigInteger(ecc_param[5], 16);
        this.ecc_gx_fieldelement = new ECFieldElement.Fp(this.ecc_p, this.ecc_gx);
        this.ecc_gy_fieldelement = new ECFieldElement.Fp(this.ecc_p, this.ecc_gy);
        this.ecc_curve = new ECCurve.Fp(this.ecc_p, this.ecc_a, this.ecc_b);
        this.ecc_point_g = new ECPoint.Fp(this.ecc_curve, this.ecc_gx_fieldelement, this.ecc_gy_fieldelement);
        this.ecc_bc_spec = new ECDomainParameters(this.ecc_curve, this.ecc_point_g, this.ecc_n);
        ECKeyGenerationParameters ecc_ecgenparam;
        ecc_ecgenparam = new ECKeyGenerationParameters(this.ecc_bc_spec, new SecureRandom());
        this.ecc_key_pair_generator = new ECKeyPairGenerator();
        this.ecc_key_pair_generator.init(ecc_ecgenparam);
    }

    @Override
    public void setReturnDataType(ReturnType mReturnType) {
        this.returnType = mReturnType;
    }

    public ReturnType getReturnType() {
        return returnType;
    }

    /**
     * 加密
     * @param content 需要加密的数据
     * @param key  密钥 (密钥需要16进制字符串,其他请使用byte[])
     * @return
     */
    @Override
    public byte[] encode(String key, byte[] content) throws Exception {
        if (key==null||content==null){
            return null;
        }
        byte[] source = new byte[content.length];
        System.arraycopy(content, 0, source, 0, content.length);
        Cipher cipher = new Cipher();
        byte[] _key=null;
        if (returnType.equals(ReturnType.TYPE_BASE64)){
            _key=UUtils.convertBase64ToBytes(key);
        }else {
            _key=UUtils.hexStringToBytes(key);
        }
        ECPoint userKey = this.ecc_curve.decodePoint(_key);
        ECPoint c1 = cipher.Init_enc(userKey);
        cipher.Encrypt(source);
        byte[] encode=c1.getEncoded();
        byte[] c3 = new byte[32];
        cipher.Dofinal(c3);
        ByteBuffer byteBuffer=ByteBuffer.allocate(encode.length+source.length+c3.length);
        byteBuffer.put(encode);
        byteBuffer.put(source);
        byteBuffer.put(c3);
        return byteBuffer.array();
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
    public byte[] decode(String key, byte[] content) throws Exception {
        if (content==null||key==null)
        {
            return null;
        }
        //加密字节数组转换为十六进制的字符串 长度变为value.length * 2
        String data = UUtils.byteToHex(content);
        /***分解加密字串
         * （C1 = C1标志位2位 + C1实体部分128位 = 130）
         * （C2 = encryptedData.length * 2 - C1长度  - C2长度）
         * （C3 = C3实体部分64位  = 64）
         */
        byte[] c1Bytes = UUtils.hexToByte(data.substring(0,130));
        int c2Len = content.length - 97;
        byte[] c2 = UUtils.hexToByte(data.substring(130,130 + 2 * c2Len));
        byte[] c3 = UUtils.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));
        byte[] _key=null;
        if (returnType.equals(ReturnType.TYPE_BASE64)){
            _key=UUtils.convertBase64ToBytes(key);
        }else {
            _key=UUtils.hexStringToBytes(key);
        }
        BigInteger userD = new BigInteger(1, _key);

        //通过C1实体字节来生成ECPoint
        ECPoint c1 =ecc_curve.decodePoint(c1Bytes);
        Cipher cipher = new Cipher();
        cipher.Init_dec(userD, c1);
        cipher.Decrypt(c2);
        cipher.Dofinal(c3);
        //返回解密结果
        return c2;
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

    public class Cipher {
        private int ct;
        private ECPoint p2;
        private Sm3Signature sm3keybase;
        private Sm3Signature sm3c3;
        private byte key[];
        private byte keyOff;

        public Cipher()
        {
            this.ct = 1;
            this.key = new byte[32];
            this.keyOff = 0;
        }

        private void Reset()
        {
            this.sm3keybase = new Sm3Signature();
            this.sm3c3 = new Sm3Signature();

            byte p[] = UUtils.byteConvert32Bytes(p2.getX().toBigInteger());
            this.sm3keybase.update(p, 0, p.length);
            this.sm3c3.update(p, 0, p.length);

            p = UUtils.byteConvert32Bytes(p2.getY().toBigInteger());
            this.sm3keybase.update(p, 0, p.length);
            this.ct = 1;
            NextKey();
        }

        private void NextKey()
        {
            Sm3Signature sm3keycur = new Sm3Signature(this.sm3keybase);
            sm3keycur.update((byte) (ct >> 24 & 0xff));
            sm3keycur.update((byte) (ct >> 16 & 0xff));
            sm3keycur.update((byte) (ct >> 8 & 0xff));
            sm3keycur.update((byte) (ct & 0xff));
            sm3keycur.doFinal(key, 0);
            this.keyOff = 0;
            this.ct++;
        }

        public ECPoint Init_enc(ECPoint userKey)
        {
            AsymmetricCipherKeyPair key =ecc_key_pair_generator.generateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
            BigInteger k = ecpriv.getD();
            ECPoint c1 = ecpub.getQ();
            this.p2 = userKey.multiply(k);
            Reset();
            return c1;
        }

        public void Encrypt(byte data[])
        {
            this.sm3c3.update(data, 0, data.length);
            for (int i = 0; i < data.length; i++)
            {
                if (keyOff == key.length)
                {
                    NextKey();
                }
                data[i] ^= key[keyOff++];
            }
        }

        public void Init_dec(BigInteger userD, ECPoint c1)
        {
            this.p2 = c1.multiply(userD);
            Reset();
        }

        public void Decrypt(byte data[])
        {
            for (int i = 0; i < data.length; i++)
            {
                if (keyOff == key.length)
                {
                    NextKey();
                }
                data[i] ^= key[keyOff++];
            }

            this.sm3c3.update(data, 0, data.length);
        }

        public void Dofinal(byte c3[])
        {
            byte p[] = UUtils.byteConvert32Bytes(p2.getY().toBigInteger());
            this.sm3c3.update(p, 0, p.length);
            this.sm3c3.doFinal(c3, 0);
            Reset();
        }
    }
}
