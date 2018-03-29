package com.mycrypto.nosymmetry;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by TF016591 on 2018/3/29.
 */
public class ECDHCoder {
    private static final String KEY_ALGORITHM = "ECDH";
    /**
     * 支持的算法
     * NONEWithECDSA
     * SHA1withECDSA
     * SHA224withECDSA
     * SHA256withECDSA
     * SHA384withECDSA
     * SHA512withECDSA
     * bc 支持 RIPEMD160withECDSA
     */
    private static final String SECERT_ALGORITHM = "AES/ECB/PKCS7Padding";

    /**
     * 长度支持 112 256 571
     */
    private static final int KEY_SIZE = 256;
    private static final String PUBLIC_KEY = "ECDSAPublicKey";
    private static final String PRIVATE_KEY = "ECDSAPrivateKey";

    static {
//        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * 初始化甲方密钥
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static Map<String, Object> initKey() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator
                .getInstance(KEY_ALGORITHM);
        generator.initialize(KEY_SIZE);
        // 生成密钥对
        KeyPair keyPair = generator.generateKeyPair();
        // 得到甲方的公钥和私钥
        ECPrivateKey ecPriKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey ecPubKey = (ECPublicKey) keyPair.getPublic();
        // 密钥保存
        Map<String, Object> map = new HashMap<>();
        map.put(PRIVATE_KEY, ecPriKey);
        map.put(PUBLIC_KEY, ecPubKey);
        return map;

    }

    /**
     * 构建乙方密钥
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey(byte[] key) throws Exception {
        // 解析甲方公钥
        // 转换公钥材料
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        // 实例化密钥工厂
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 产生公钥
        ECPublicKey pubKey = (ECPublicKey) factory
                .generatePublic(x509EncodedKeySpec);
        // 有甲方构建乙方密钥
        ECParameterSpec dhParameterSpec = pubKey.getParams();
        // 实例化密钥队生成器
        KeyPairGenerator generator = KeyPairGenerator.getInstance(factory
                .getAlgorithm());
        // 初始化密钥对生成器
        generator.initialize(dhParameterSpec);
        // 产生密钥对
        KeyPair keyPair = generator.generateKeyPair();
        // 乙方公钥,私钥
        ECPublicKey ecPubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey ecPriKey = (ECPrivateKey) keyPair.getPrivate();
        // 保存
        Map<String, Object> map = new HashMap<>();
        map.put(PRIVATE_KEY, ecPriKey);
        map.put(PUBLIC_KEY, ecPubKey);
        return map;
    }

    /**
     * 加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, SECERT_ALGORITHM);
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    /**
     * 解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, SECERT_ALGORITHM);
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey)
            throws Exception {
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 初始化公钥
        // 密钥转换材料
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey);
        // 产生公钥
        PublicKey publicKey2 = factory.generatePublic(x509EncodedKeySpec);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey);
        // 产生私钥
        PrivateKey privateKey2 = factory.generatePrivate(pkcs8EncodedKeySpec);
        KeyAgreement keyAgreement = KeyAgreement.getInstance(factory
                .getAlgorithm());
        // 初始化
        keyAgreement.init(privateKey2);
        keyAgreement.doPhase(publicKey2, true);
        // 生成本地密钥
        SecretKey secretKey = keyAgreement.generateSecret(SECERT_ALGORITHM);
        return secretKey.getEncoded();
    }

    public static byte[] generateSecretKey(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException {

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);

        return ka.generateSecret();
    }

    /**
     * 获取私钥
     *
     * @param keyMap
     * @return
     */
    public static byte[] getPrivateKey(Map<String, Object> keyMap) {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

    /**
     * 获取公钥
     *
     * @param keyMap
     * @return
     */
    public static byte[] getPublicKey(Map<String, Object> keyMap) {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return key.getEncoded();
    }

    public static void main(String[] args) throws Exception {
        // 甲方密钥对
        Map<String, Object> keyMap = initKey();
        byte[] pubKey1 = getPublicKey(keyMap);
        byte[] priKey1 = getPrivateKey(keyMap);
        System.out.println("甲方公钥:\t" + Base64.encodeBase64String(pubKey1));
        System.out.println("甲方私钥:\t" + Base64.encodeBase64String(priKey1));
        // 有甲方公钥产生本地密钥对
        Map<String, Object> keyMap2 = initKey(pubKey1);

        byte[] pubKey2 = getPublicKey(keyMap2);
        byte[] priKey2 = getPrivateKey(keyMap2);
        System.out.println("乙方公钥:\t" + Base64.encodeBase64String(pubKey2));
        System.out.println("乙方私钥:\t" + Base64.encodeBase64String(priKey2));

        byte[] key1 = getSecretKey(pubKey2, priKey1);
        System.out.println("甲方本地密钥:\t" + Base64.encodeBase64String(key1));
        byte[] key2 = getSecretKey(pubKey1, priKey2);
        System.out.println("乙方本地密钥:\t" + Base64.encodeBase64String(key2));

        System.out.println("\n=====甲方想乙方发送加密数据=====");
        String input = "密钥交换算法";
        System.out.println("原文:" + input);
        System.out.println("----使用甲方本地密钥对数据加密-----");
        byte[] code1 = encrypt(input.getBytes(), key1);
        System.out.println("加密:" + Base64.encodeBase64String(code1));
        System.out.println("----使用乙方本地密钥对数据加密-----");
        byte[] decode1 = decrypt(code1, key2);
        System.out.println("解密:" + new String(decode1));

        System.out.println("\n====乙方向甲方发送加密数据====");
        String input2 = "dh";
        System.out.println("原文:" + input2);
        System.out.println("\n====使用乙方本地密钥对数据加密-====");
        // 使用乙方本地密钥对数据加密


        byte[] code2 = encrypt(input2.getBytes(), key2);
        System.out.println("加密:" + Base64.encodeBase64String(code2));
        System.out.println("\n====使用甲方本地密钥对数据加密-====");
        byte[] decode2 = decrypt(code2, key1);
        System.out.println("解密:" + new String(decode2));
    }

}
