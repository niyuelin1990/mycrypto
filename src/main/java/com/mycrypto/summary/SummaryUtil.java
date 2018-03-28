package com.mycrypto.summary;

import com.mycrypto.summary.jce.SpongyCastleProvider;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * 摘要加密算法
 * Created by TF016591 on 2018/3/28.
 */
public class SummaryUtil {
    // MD系列
    private static final String KEY_MD2 = "MD2";
    private static final String KEY_MD5 = "MD5";

    //SHA 系列
    private static final String KEY_SHA = "SHA";
    private static final String KEY_SHA265 = "SHA-256";
    private static final String KEY_SHA384 = "SHA-384";
    private static final String KEY_SHA512 = "SHA-512";
    //SHA3 系列
    private static final String KEY_ETH_KECCAK_256 = "ETH-KECCAK-256";
    private static final String KEY_ETH_KECCAK_512 = "ETH-KECCAK-512";

    static {
        Security.addProvider(SpongyCastleProvider.getInstance());
    }

    /**
     * MD2加密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encryptMD2(byte[] data) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance(KEY_MD2);
        md5.update(data);
        return md5.digest();
    }

    /**
     * MD5加密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encryptMD5(byte[] data) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance(KEY_MD5);
        md5.update(data);
        return md5.digest();
    }


    // 签名
    public static String sign(String str, String type) {
        String s = encrypt(str, type);
        return s;
    }

    private static String encrypt(String strSrc, String encName) {
        MessageDigest md;
        String strDes;
        byte[] bt = strSrc.getBytes();
        try {
            md = MessageDigest.getInstance(encName);
            md.update(bt);
            strDes = bytes2Hex(md.digest()); // to HexString
        } catch (NoSuchAlgorithmException e) {
            System.out.println("摘要加密失败！" + e.toString());
            return null;
        }
        return strDes;
    }

    //2进制转16进制
    private static String bytes2Hex(byte[] bts) {
        StringBuffer des = new StringBuffer();
        String tmp;
        for (int i = 0; i < bts.length; i++) {
            tmp = (Integer.toHexString(bts[i] & 0xFF));
            if (tmp.length() == 1) {
                des.append("0");
            }
            des.append(tmp);
        }
        //或者new BigInteger(1,bts).toString(16)
        return des.toString();
    }

    public static byte[] sha3(byte[] input) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("ETH-KECCAK-256");
            digest.update(input);
            return digest.digest();
        }catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sha3512(byte[] input) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("ETH-KECCAK-512");
            digest.update(input);
            return digest.digest();
        }catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }



    public static void main(String[] args) throws Exception {
        String inputStr = "简单加密";
        byte[] inputData = inputStr.getBytes();
        System.out.println("原文:" + inputStr);
        System.out.println("=======MD算法使用,注意已经不够安全======");
        // 验证MD2对于同一内容加密是否一致
        System.out.println("MD2:" + new BigInteger(1, SummaryUtil.encryptMD2(inputData)).toString(16));
        // 验证MD5对于同一内容加密是否一致
        System.out.println("MD5:" + new BigInteger(1, SummaryUtil.encryptMD5(inputData)).toString(16));
        System.out.println("MD5 第二种方式:" + SummaryUtil.sign(inputStr, KEY_MD5));

        System.out.println("=======SHA算法使用,推荐至少SHA2-256======");
        System.out.println("采用" + KEY_SHA + "加密之后的串为：" + SummaryUtil.sign(inputStr, KEY_SHA));
        System.out.println("采用" + KEY_SHA265 + "加密之后的串为：" + SummaryUtil.sign(inputStr, KEY_SHA265));
        System.out.println("采用" + KEY_SHA384 + "加密之后的串为：" + SummaryUtil.sign(inputStr, KEY_SHA384));
        System.out.println("采用" + KEY_SHA512 + "加密之后的串为：" + SummaryUtil.sign(inputStr, KEY_SHA512));
        System.out.println("=======SHA3算法使用,安全系数更高======");
        System.out.println("采用" + KEY_ETH_KECCAK_256 + "加密之后的串为：" + SummaryUtil.sign(inputStr, KEY_ETH_KECCAK_256));
        System.out.println("采用" + KEY_ETH_KECCAK_512 + "加密之后的串为：" + SummaryUtil.sign(inputStr, KEY_ETH_KECCAK_512));

    }
}
