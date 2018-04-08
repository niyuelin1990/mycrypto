package com.mycrypto.symmetry;


import org.spongycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 对称加密AES
 * Created by TF016591 on 2018/3/29.
 */
public class AESUtil {
    private static final String KEY_AES = "AES";
    // ECB工作模式(CBC等)，填充模式(PKCS5Padding等)
    private static final String KEY_CHRHER_AES = "AES/ECB/PKCS5Padding";

    /*
     * 加密encrypt
     * @param content:
     * @param password:
     */
    private static byte[] encrypt(String content, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, KEY_AES);

        Cipher cipher = Cipher.getInstance(KEY_CHRHER_AES);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(content.getBytes("utf-8"));

    }

    /*
     * 解密decrypt
     * @param content:
     * @param password:
     */
    private static byte[] decrypt(byte[] content, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, KEY_AES);

        Cipher cipher = Cipher.getInstance(KEY_CHRHER_AES);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(content);
    }

    /**
     * 取随机key
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] initKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance(KEY_AES);
        //支持128 192 256位
        kg.init(128);
        SecretKey secretKey = kg.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 通过已知key，生成秘钥
     *
     * @param strKey
     * @return
     * @throws Exception
     */
    public static SecretKey getUseKey(String strKey) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KEY_AES);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(strKey.getBytes());
        generator.init(128, secureRandom);
        return generator.generateKey();
    }

    /**
     * 通过已知key，生成秘钥 加密
     *
     * @param content
     * @param key
     * @return
     * @throws Exception
     */
    private static byte[] encryptUse(String content, String key) throws Exception {
        SecretKey secretKey = getUseKey(key);
        byte[] encodeFormat = secretKey.getEncoded();

        SecretKeySpec secretKeySpec = new SecretKeySpec(encodeFormat, KEY_AES);
        Cipher cipher = Cipher.getInstance(KEY_CHRHER_AES);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(content.getBytes());
    }

    /**
     * 通过已知key，生成秘钥 解密
     *
     * @param content
     * @param key
     * @return
     */
    private static byte[] decryptUse(byte[] content, String key) throws Exception {
        SecretKey secretKey = getUseKey(key);
        byte[] encodeFormat = secretKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(encodeFormat, "AES");
        Cipher cipher = Cipher.getInstance(KEY_CHRHER_AES);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(content);
    }


    public static void main(String[] args) throws Exception {
        String inputStr = "简单密文";
        System.out.println("原文:" + inputStr);
        byte[] key = AESUtil.initKey();
        System.out.println("秘钥：" + Hex.toHexString(key));

        byte[] inputData = AESUtil.encrypt(inputStr, key);
        System.out.println("加密：" + Hex.toHexString(inputData));
        byte[] outData = AESUtil.decrypt(inputData, key);
        System.out.println("解密：" + new String(outData));

        System.out.println("========= 通过已知key，生成秘钥===========");
        String password = "example";
        System.out.println("秘钥：" + Hex.toHexString(AESUtil.getUseKey(password).getEncoded()));

        byte[] inputData2 = AESUtil.encryptUse(inputStr, password);
        System.out.println("加密：" + Hex.toHexString(inputData2));
        byte[] outData2 = AESUtil.decryptUse(inputData2, password);
        System.out.println("解密：" + new String(outData2));
    }
}
