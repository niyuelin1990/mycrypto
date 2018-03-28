package com.mycrypto.summary;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

/**
 * 摘要加密算法  MAC
 * Created by TF016591 on 2018/3/28.
 */
public class SummaryUtil2 {

    //Hmac MD系列
    public static final String KEY_MAC_MD5 = "HmacMD5";
    public static final String KEY_MAC_SHA1 = "HmacSHA1";
    public static final String KEY_MAC_SHA256 = "HmacSHA256";
    public static final String KEY_MAC_SHA384 = "HmacSHA384";
    public static final String KEY_MAC_SHA512 = "HmacSHA512";

    /**
     * 初始化HMAC密钥
     *
     * @return
     * @throws Exception
     */
    public static String initMacKey(String encName) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(encName);

        SecretKey secretKey = keyGenerator.generateKey();
        return Hex.toHexString(secretKey.getEncoded());
    }

    /**
     * HMAC加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptHMAC(byte[] data, String key, String encName) throws Exception {
        SecretKey secretKey = new SecretKeySpec(Hex.decode(key), encName);
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        mac.init(secretKey);

        return mac.doFinal(data);
    }


    public static void main(String[] args) throws Exception {
        String inputStr = "简单加密";
        byte[] inputData = inputStr.getBytes();
        System.out.println("原文:" + inputStr);

        String key = SummaryUtil2.initMacKey(KEY_MAC_MD5);
        System.out.println("使用:" + KEY_MAC_MD5 + ", Mac密钥:" + key);
        System.out.println("使用:" + KEY_MAC_MD5 + ",HMAC:" + new BigInteger(1, SummaryUtil2.encryptHMAC(inputData, key, KEY_MAC_MD5)).toString(16));

        key = SummaryUtil2.initMacKey(KEY_MAC_SHA1);
        System.out.println("使用:" + KEY_MAC_SHA1 + ", Mac密钥:" + key);
        System.out.println("使用:" + KEY_MAC_SHA1 + ",HMAC:" + new BigInteger(1, SummaryUtil2.encryptHMAC(inputData, key, KEY_MAC_SHA1)).toString(16));

        key = SummaryUtil2.initMacKey(KEY_MAC_SHA256);
        System.out.println("使用:" + KEY_MAC_SHA256 + ", Mac密钥:" + key);
        System.out.println("使用:" + KEY_MAC_SHA256 + ",HMAC:" + new BigInteger(1, SummaryUtil2.encryptHMAC(inputData, key, KEY_MAC_SHA256)).toString(16));

        key = SummaryUtil2.initMacKey(KEY_MAC_SHA384);
        System.out.println("使用:" + KEY_MAC_SHA384 + ", Mac密钥:" + key);
        System.out.println("使用:" + KEY_MAC_SHA384 + ",HMAC:" + new BigInteger(1, SummaryUtil2.encryptHMAC(inputData, key, KEY_MAC_SHA384)).toString(16));

        key = SummaryUtil2.initMacKey(KEY_MAC_SHA512);
        System.out.println("使用:" + KEY_MAC_SHA512 + ", Mac密钥:" + key);
        System.out.println("使用:" + KEY_MAC_SHA512 + ",HMAC:" + new BigInteger(1, SummaryUtil2.encryptHMAC(inputData, key, KEY_MAC_SHA512)).toString(16));

    }
}
