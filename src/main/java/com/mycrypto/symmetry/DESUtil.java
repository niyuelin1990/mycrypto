package com.mycrypto.symmetry;

import org.spongycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 对称加密DES
 * Created by TF016591 on 2018/3/29.
 */
public class DESUtil {
    // DES
    private static final String KEY_DES = "DES";
    // ECB工作模式(CBC等)，填充模式(PKCS5Padding等)
    private static final String KEY_CHRHER_DES = "DES/ECB/PKCS5Padding";
    //ECB（电码本模式），CBC（加密块链模式）
    private static final String KEY_CHRHER2_DES = "DES/CBC/PKCS5Padding";

    /**
     * 生成秘钥
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] initKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance(KEY_DES);
        kg.init(56);
        SecretKey secretKey = kg.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 转换秘钥
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static Key toKey(byte[] key) throws Exception {
        DESKeySpec keySpec = new DESKeySpec(key);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_DES);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey;
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
        Key k = toKey(key);
        Cipher cipher = Cipher.getInstance(KEY_CHRHER_DES);
        cipher.init(Cipher.DECRYPT_MODE, k);
        return cipher.doFinal(data);
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
        Key k = toKey(key);
        Cipher cipher = Cipher.getInstance(KEY_CHRHER_DES);
        cipher.init(Cipher.ENCRYPT_MODE, k);
        return cipher.doFinal(data);
    }


    /**
     * 固定秘钥 解密
     *
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, String skey) throws Exception {
        byte[] key = skey.getBytes();
        IvParameterSpec iv = new IvParameterSpec(key);
        DESKeySpec desKey = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DES);
        SecretKey securekey = keyFactory.generateSecret(desKey);
        Cipher cipher = Cipher.getInstance(KEY_CHRHER2_DES);
        cipher.init(Cipher.DECRYPT_MODE, securekey, iv);
        // 真正开始解密操作
        return cipher.doFinal(data);
    }

    /**
     * 固定秘钥 加密
     *
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, String skey) throws Exception {
        byte[] key = skey.getBytes();
        IvParameterSpec iv = new IvParameterSpec(key);
        DESKeySpec desKey = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DES);
        SecretKey securekey = keyFactory.generateSecret(desKey);
        System.out.println("密码:" + Hex.toHexString(securekey.getEncoded()));

        Cipher cipher = Cipher.getInstance(KEY_CHRHER2_DES);
        cipher.init(Cipher.ENCRYPT_MODE, securekey, iv);
        return cipher.doFinal(data);
    }

    /**
     * 固定秘钥 解密
     *
     * @throws Exception
     */
    public static byte[] decrypt2(byte[] data, String skey) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_DES);
        keyGenerator.init(56, new SecureRandom(skey.getBytes()));
        SecretKey key2 = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance(KEY_CHRHER_DES);
        cipher.init(Cipher.DECRYPT_MODE, key2);
        // 真正开始解密操作
        return cipher.doFinal(data);
    }

    /**
     * 固定秘钥 加密
     *
     * @throws Exception
     */
    public static byte[] encrypt2(byte[] data, String skey) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_DES);
        keyGenerator.init(56, new SecureRandom(skey.getBytes()));
        SecretKey key2 = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance(KEY_CHRHER_DES);
        cipher.init(Cipher.ENCRYPT_MODE, key2);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        String inputStr = "简单密文";
        byte[] inputData = inputStr.getBytes();
        System.out.println("原文:" + inputStr);
        byte[] key = DESUtil.initKey();
        System.out.println("秘钥：" + Hex.toHexString(key));

        inputData = DESUtil.encrypt(inputData, key);
        System.out.println("加密：" + Hex.toHexString(inputData));

        byte[] outData = DESUtil.decrypt(inputData, key);
        System.out.println("解密：" + new String(outData));
        System.out.println("=========固定秘钥===========");
        byte[] inputData2 = inputStr.getBytes();
        String sKey = "01234567";
        System.out.println("原文:" + inputStr + ", 秘钥:" + sKey);

        inputData2 = DESUtil.encrypt(inputData2, sKey);
        System.out.println("加密：" + Hex.toHexString(inputData2));

        byte[] outData2 = DESUtil.decrypt(inputData2, sKey);
        System.out.println("解密：" + new String(outData2));

        System.out.println("=========固定秘钥2===========");
        byte[] inputData3 = inputStr.getBytes();
        //key为8个字节，实际用了56位； 后面随机数用key作为种子seed生成
        String sKey3 = "01234567";
        System.out.println("原文:" + inputStr + ", 秘钥:" + sKey);

        inputData3 = DESUtil.encrypt(inputData3, sKey3);
        System.out.println("加密：" + Hex.toHexString(inputData3));

        byte[] outData3 = DESUtil.decrypt(inputData3, sKey3);
        System.out.println("解密：" + new String(outData3));

    }
}
