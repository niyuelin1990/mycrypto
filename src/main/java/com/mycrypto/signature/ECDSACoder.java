package com.mycrypto.signature;

import com.mycrypto.summary.jce.ECKeyFactory;
import com.mycrypto.summary.jce.SpongyCastleProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.spongycastle.jce.spec.*;
import org.spongycastle.math.ec.*;
import org.spongycastle.util.encoders.Hex;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by TF016591 on 2018/3/29.
 */
public class ECDSACoder {
    /**
     * 数字签名 密钥算法
     */
    private static final String KEY_ALGORITHM = "ECDSA";

    private static final String KEY_ALGORITHM2 = "EC";
    private static final int KEY_SIZE = 256;

    /**
     * 数字签名 签名/验证算法
     * <p>
     * Bouncy Castle支持以下7种算法 NONEwithECDSA RIPEMD160withECDSA SHA1withECDSA
     * SHA224withECDSA SHA256withECDSA SHA384withECDSA SHA512withECDSA
     */
    private static final String SIGNATURE_ALGORITHM = "SHA512withECDSA";

    /**
     * 公钥
     */
    private static final String PUBLIC_KEY = "ECDSAPublicKey";

    /**
     * 私钥
     */
    private static final String PRIVATE_KEY = "ECDSAPrivateKey";

    /**
     * 初始化密钥
     *
     * @return Map 密钥Map
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {

        // 加入BouncyCastleProvider支持
        Security.addProvider(new BouncyCastleProvider());

        BigInteger p = new BigInteger(
                "883423532389192164791648750360308885314476597252960362792450860609699839");

        ECFieldFp ecFieldFp = new ECFieldFp(p);

        BigInteger a = new BigInteger(
                "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
                16);

        BigInteger b = new BigInteger(
                "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
                16);

        EllipticCurve ellipticCurve = new EllipticCurve(ecFieldFp, a, b);

        BigInteger x = new BigInteger(
                "110282003749548856476348533541186204577905061504881242240149511594420911");

        BigInteger y = new BigInteger(
                "869078407435509378747351873793058868500210384946040694651368759217025454");

        ECPoint g = new ECPoint(x, y);

        BigInteger n = new BigInteger(
                "883423532389192164791648750360308884807550341691627752275345424702807307");

        ECParameterSpec ecParameterSpec = new ECParameterSpec(ellipticCurve, g,
                n, 1);

        // 实例化密钥对儿生成器
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);

        // 初始化密钥对儿生成器
        kpg.initialize(ecParameterSpec, new SecureRandom());

        // 生成密钥对儿
        KeyPair keypair = kpg.generateKeyPair();

        ECPublicKey publicKey = (ECPublicKey) keypair.getPublic();

        ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();

        // 封装密钥
        Map<String, Object> map = new HashMap<String, Object>(2);

        map.put(PUBLIC_KEY, publicKey);
        map.put(PRIVATE_KEY, privateKey);

        return map;
    }

    public static Map<String, Object> initKey2() throws Exception {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM2);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM2, SpongyCastleProvider.getInstance());
        ECGenParameterSpec SECP256K1_CURVE = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(SECP256K1_CURVE, new SecureRandom());
        //初始化密钥对生成器
//        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        //得到公钥和私钥
        if (pubKey instanceof BCECPublicKey) {
            org.spongycastle.math.ec.ECPoint pub = ((BCECPublicKey) pubKey).getQ();
            System.out.println("公钥:"+Hex.toHexString(pub.getEncoded(false)));
        }
        PrivateKey privKey = keyPair.getPrivate();
        String privString = Hex.toHexString(bigIntegerToBytes(((BCECPrivateKey) privKey).getD(), 32));
        System.out.println("私钥:"+privString);
        BigInteger privateKey2 = new BigInteger(privString, 16);
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
       org.spongycastle.jce.spec.ECParameterSpec CURVE_SPEC = new org.spongycastle.jce.spec.ECParameterSpec(params.getCurve(), params.getG(), params.getN(), params.getH());
        ECDomainParameters CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        org.spongycastle.math.ec.ECPoint pub2 = CURVE.getG().multiply(privateKey2);
        System.out.println("公钥:"+Hex.toHexString(pub2.getEncoded(false)));

        PrivateKey privKey3= ECKeyFactory
                .getInstance(SpongyCastleProvider.getInstance())
                .generatePrivate(new org.spongycastle.jce.spec.ECPrivateKeySpec(privateKey2, CURVE_SPEC));
        System.out.println("私钥:"+ Hex.toHexString(bigIntegerToBytes(((BCECPrivateKey) privKey3).getD(), 32)));

        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) privKey3;
        //获取私钥D
        BigInteger D = privateKey.getS();
        //得到公钥的横纵坐标
        BigInteger publicKeyX = publicKey.getW().getAffineX();
        BigInteger publicKeyY = publicKey.getW().getAffineY();
        //得到生成椭圆曲线的参数a,b
        java.security.spec.ECParameterSpec ecParams = privateKey.getParams();
        BigInteger curveA = ecParams.getCurve().getA();
        BigInteger curveB = ecParams.getCurve().getB();
        //获取此椭圆有限字段的素数 qq
        ECFieldFp fieldFp = (ECFieldFp) ecParams.getCurve().getField();
        BigInteger q = fieldFp.getP();
        //获取椭圆的基点的x,y值
        BigInteger coordinatesX = ecParams.getGenerator().getAffineX();
        BigInteger coordinatesY = ecParams.getGenerator().getAffineY();
        //基点的阶
        BigInteger coordinatesG = ecParams.getOrder();
        //获取余因子
        int h = ecParams.getCofactor();


        //创建基于指定值的椭圆曲线域参数
        ECParameterSpec ecParameterSpec = new ECParameterSpec(new EllipticCurve(new ECFieldFp(q), curveA, curveB), new ECPoint(coordinatesX, coordinatesY), coordinatesG, h);
        ECPublicKey publicKey1 = new ECPublicKeyImpl(new ECPoint(publicKeyX, publicKeyY), ecParameterSpec);
        ECPrivateKey privateKey1 = new ECPrivateKeyImpl(D, ecParameterSpec);
        // 封装密钥
        Map<String, Object> map = new HashMap<String, Object>(2);

        map.put(PUBLIC_KEY, publicKey1);
        map.put(PRIVATE_KEY, privateKey1);
        return map;
    }

    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        if (b == null)
            return null;
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        int start = (biBytes.length == numBytes + 1) ? 1 : 0;
        int length = Math.min(biBytes.length, numBytes);
        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;
    }

    /**
     * 取得私钥
     *
     * @param keyMap 密钥Map
     * @return byte[] 私钥
     * @throws Exception
     */
    public static byte[] getPrivateKey(Map<String, Object> keyMap)
            throws Exception {

        Key key = (Key) keyMap.get(PRIVATE_KEY);

        return key.getEncoded();
    }

    /**
     * 取得公钥
     *
     * @param keyMap 密钥Map
     * @return byte[] 公钥
     * @throws Exception
     */
    public static byte[] getPublicKey(Map<String, Object> keyMap)
            throws Exception {

        Key key = (Key) keyMap.get(PUBLIC_KEY);

        return key.getEncoded();
    }

    /**
     * 签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return byte[] 数字签名
     * @throws Exception
     */
    public static byte[] sign(byte[] data, byte[] privateKey) throws Exception {

        // 加入BouncyCastleProvider支持
        Security.addProvider(new BouncyCastleProvider());

        // 转换私钥材料
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);

        // 实例化密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 取私钥匙对象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 实例化Signature
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);

        // 初始化Signature
        signature.initSign(priKey);

        // 更新
        signature.update(data);

        // 签名
        return signature.sign();
    }

    /**
     * 校验
     *
     * @param data      待校验数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return boolean 校验成功返回true 失败返回false
     * @throws Exception
     */
    public static boolean verify(byte[] data, byte[] publicKey, byte[] sign)
            throws Exception {

        // 加入BouncyCastleProvider支持
        Security.addProvider(new BouncyCastleProvider());

        // 转换公钥材料
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);

        // 实例化密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 生成公钥
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        // 实例化Signature
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);

        // 初始化Signature
        signature.initVerify(pubKey);

        // 更新
        signature.update(data);

        // 验证
        return signature.verify(sign);
    }

    public static void main(String[] args) throws Exception {
        byte[] publicKey; // 公钥

        byte[] privateKey; // 私钥
        Map<String, Object> keyMap = ECDSACoder.initKey2();

        publicKey = ECDSACoder.getPublicKey(keyMap);

        privateKey = ECDSACoder.getPrivateKey(keyMap);

        System.out.println("公钥: \n" + Hex.toHexString(publicKey));
        System.out.println("私钥： \n" + Hex.toHexString(privateKey));
        String inputStr = "ECDSA数字签名";
        byte[] data = inputStr.getBytes();

        // 产生签名
        byte[] sign = ECDSACoder.sign(data, privateKey);
        System.out.println("签名:\r" + Hex.toHexString(sign));

        // 验证签名
        boolean status = ECDSACoder.verify(data, publicKey, sign);
        System.out.println("状态:\r" + status);

    }

}
