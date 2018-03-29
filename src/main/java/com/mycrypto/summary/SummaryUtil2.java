package com.mycrypto.summary;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.util.encoders.Hex;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.RIPEMD256Digest;
import org.spongycastle.crypto.digests.RIPEMD320Digest;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Security;
import java.util.zip.CRC32;

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

    public static final String KEY_MAC_MD2 = "HmacMD2";
    public static final String KEY_MAC_MD4 = "HmacMD4";
    public static final String KEY_MAC_SHA224 = "HmacSHA224";
    public static final String KEY_HMAC_MD160 = "HmacRipeMD160";

    public static final String[] KEY_MACS = {KEY_MAC_MD5, KEY_MAC_SHA1, KEY_MAC_SHA256, KEY_MAC_SHA384, KEY_MAC_SHA512, KEY_MAC_MD2, KEY_MAC_MD4, KEY_MAC_SHA224, KEY_HMAC_MD160};

    //RIPEMD 算法
    public static final String KEY_RIPEMD_160 = "RipeMD160";
    public static final String KEY_RIPEMD_256 = "RipeMD256";
    public static final String KEY_RIPEMD_320 = "RipeMD320";

    public static final String[] KEY_RIPEMDS = {KEY_RIPEMD_160, KEY_RIPEMD_256, KEY_RIPEMD_320};

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

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

    /**
     * HMAC加密,明文Key
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptMHMAC(byte[] data, String key, String encName) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), encName);
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        mac.init(secretKey);

        return mac.doFinal(data);
    }

    /**
     * RipeMD算法 针对MD4和MD5算法缺陷分析提出的算法
     *
     * @param data
     * @param encName
     * @return
     */
    public static byte[] ripemd(byte[] data, String encName) {
        Digest digest = null;
        if (encName == KEY_RIPEMD_160) {
            digest = new RIPEMD160Digest();
        } else if (encName == KEY_RIPEMD_256) {
            digest = new RIPEMD256Digest();
        } else if (encName == KEY_RIPEMD_320) {
            digest = new RIPEMD320Digest();
        }
        if (data != null) {
            byte[] resBuf = new byte[digest.getDigestSize()];
            digest.update(data, 0, data.length);
            digest.doFinal(resBuf, 0);
            return resBuf;
        }
        throw new NullPointerException("Can't hash a NULL value");
    }

    /**
     * 用于校验文件是否修改
     *
     * @param filePath
     * @return
     * @throws Exception
     */
    public static String getFileMd5Digest(String filePath) throws Exception {
        FileInputStream file = new FileInputStream(new File(filePath));
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] buffer = new byte[1024];
        for (int read = file.read(buffer, 0, 1024); read > -1; read = file.read(buffer, 0, 1024)) {
            digest.update(buffer, 0, read);
        }
        return Hex.toHexString(digest.digest());
    }

    /**
     * CRC即循环冗余校验码（Cyclic Redundancy Check）：是数据通信领域中最常用的一种差错校验码，
     * 其特征是信息字段和校验字段的长度可以任意选定。
     *
     * @param data
     * @return
     */
    public static String crcDigest(byte[] data) {
        CRC32 crc32 = new CRC32();
        crc32.update(data);
        return Long.toHexString(crc32.getValue());
    }

    public static void main(String[] args) throws Exception {
        String inputStr = "简单加密sf";
        byte[] inputData = inputStr.getBytes();
        System.out.println("原文:" + inputStr);

        for (String mac : KEY_MACS) {
            String key = SummaryUtil2.initMacKey(mac);
            System.out.println("使用:" + mac + ", Mac密钥:" + key);
            System.out.println("使用:" + mac + ",HMAC:" + new BigInteger(1, SummaryUtil2.encryptHMAC(inputData, key, mac)).toString(16));
        }
        System.out.println();
        for (String mac : KEY_MACS) {
            System.out.println("使用2:" + mac + ",HMAC:" + new BigInteger(1, SummaryUtil2.encryptMHMAC(inputData, inputStr, mac)).toString(16));
        }
        System.out.println();
        for (String ripemd : KEY_RIPEMDS) {
            System.out.println("使用:" + ripemd + ",ripemd:" + new BigInteger(1, SummaryUtil2.ripemd(inputData, ripemd)).toString(16));
        }

        System.out.println("文件MD5使用:" + SummaryUtil2.getFileMd5Digest("D:\\settings.xml"));
        System.out.println("crc使用:" + SummaryUtil2.crcDigest(inputData));
    }
}
