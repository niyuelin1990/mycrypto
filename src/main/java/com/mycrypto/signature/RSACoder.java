package com.mycrypto.signature;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * Created by TF016591 on 2018/3/29.
 */
public class RSACoder {
    /**
     * 数字签名 密钥算法
     */
    public static final String KEY_ALGORITHM = "RSA";
    /**
     * 数字签名 签名/验证算法
     */
    public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";
    /**
     * rsa密钥长度默认是1024 迷药必须是64的倍数 范围 512 - 65536
     */
    private static final int KEY_SIZE = 512;

    /**
     * 私钥揭秘
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, byte[] key)
            throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = factory.generatePrivate(keySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥解密
     *
     * @param data
     * @param encodedKey
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, byte[] encodedKey)
            throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 生成公钥
        PublicKey publicKey = factory.generatePublic(keySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 公钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] key)
            throws Exception {

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = factory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] key)
            throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = factory.generatePrivate(keySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 签名
     *
     * @param date
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] date, byte[] privateKey) throws Exception {
        // 转换成私钥材料
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey);
        // 实例化迷药工厂
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 获取私钥对象
        PrivateKey privateKey2 = keyFactory
                .generatePrivate(pkcs8EncodedKeySpec);
        // 实例化密钥签名类 signature
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey2);
        signature.update(date);
        return signature.sign();
    }

    public static boolean verify(byte[] data, byte[] publicKey, byte[] sign)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidKeyException, SignatureException {
        // 转换成公钥材料
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKey);
        // 实例化密钥工厂
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 生成公钥
        PublicKey key = factory.generatePublic(encodedKeySpec);
        // 实例化签名认真 signature
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        // 初始化signature
        signature.initVerify(key);
        // 更新
        signature.update(data);
        // 验证
        return signature.verify(sign);
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

    /**
     * 初始化密钥
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static Map<String, Object> initKey() throws NoSuchAlgorithmException {
        // 实例化密钥生成器
        KeyPairGenerator generator = KeyPairGenerator
                .getInstance(KEY_ALGORITHM);
        // 初始化迷药生成器
        SecureRandom random = new SecureRandom();

        generator.initialize(KEY_SIZE, random);
        // 生成密钥对
        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey puKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey prKry = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<>();
        keyMap.put(PRIVATE_KEY, prKry);
        keyMap.put(PUBLIC_KEY, puKey);
        return keyMap;

    }

    /**
     * 获取密钥
     *
     * @param key
     * @return
     * @throws DecoderException
     */
    public static byte[] getKey(String key) throws DecoderException {
        return Hex.decodeHex(key.toCharArray());
    }

    public static void main(String[] args) throws Exception {
        long s = System.currentTimeMillis();
        Map<String, Object> ketMap = initKey();
        byte[] priKey = getPrivateKey(ketMap);
        byte[] pubKey = getPublicKey(ketMap);
        System.out.println("公钥:\t" + Base64.encodeBase64String(pubKey));
        System.out.println("私钥:\t" + Base64.encodeBase64String(priKey));

        System.out.println("\n----私钥加密---公钥揭秘---------");
        byte[] data = "rsa加密算法".getBytes();
        // 私钥加密
        byte[] encodeData1 = encryptByPrivateKey(data, priKey);
        System.out.println("加密后:\t" +Hex.encodeHexString(encodeData1));
        // 公钥解密
        byte[] decodeData1 = decryptByPublicKey(encodeData1, pubKey);
        System.out.println("公钥解密:\t" + new String(decodeData1));
        System.out.println("\n----公钥加密---私钥揭秘---------");
        // 公钥加密
        byte[] encodeData2 = encryptByPublicKey(data, pubKey);
        System.out.println("加密后:\t" + Hex.encodeHexString(encodeData2));
        // 私钥解密
        byte[] decodeData2 = decryptByPrivateKey(encodeData2, priKey);
        System.out.println("私钥解密:\t" + new String(decodeData2));
        System.out.println(System.currentTimeMillis() - s);


    }
}
