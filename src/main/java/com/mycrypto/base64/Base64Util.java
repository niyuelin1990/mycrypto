package com.mycrypto.base64;

import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.UnsupportedEncodingException;

/**
 * base64
 * Created by TF016591 on 2018/3/28.
 */
public class Base64Util {
    private static final String UTF_8 = "UTF-8";

    /**
     * BASE64  Decode
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    /**
     * BASE64  Encode
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    /**
     * commons-codec  base64 加密操作
     */
    public static String encodeData(String inputData) throws UnsupportedEncodingException {
        if (null == inputData) {
            return null;
        }
        return new String(Base64.encodeBase64(inputData.getBytes(UTF_8)), UTF_8);
    }

    /**
     * commons-codec  base64 解密
     *
     * @param inputData
     * @return
     * @throws UnsupportedEncodingException
     */
    public static String decodeData(String inputData) throws UnsupportedEncodingException {
        if (null == inputData) {
            return null;
        }
        return new String(Base64.decodeBase64(inputData.getBytes(UTF_8)), UTF_8);

    }
    /**
     * commons-codec  base64 url 加密操作
     */
    public static String urlEncodeData(String inputData) throws UnsupportedEncodingException {
        if (null == inputData) {
            return null;
        }
        return new String(Base64.encodeBase64URLSafe(inputData.getBytes(UTF_8)), UTF_8);
    }


    public static void main(String[] args) throws Exception {
        String inputStr = "简单加密";
        System.out.println("原文:/n" + inputStr);

        byte[] inputData = inputStr.getBytes();
        String code = Base64Util.encryptBASE64(inputData);
        System.out.println("BASE64加密后:" + code);

        byte[] output = Base64Util.decryptBASE64(code);
        String outputStr = new String(output);
        System.out.println("BASE64解密后:" + outputStr);


        System.out.println("=======commons-codec base64 推荐使用======");
        String encodeData = Base64Util.encodeData(inputStr);
        System.out.println("BASE64加密后:" + encodeData);
        System.out.println("BASE64解密后:" + Base64Util.decodeData(encodeData));

        System.out.println("=======commons-codec base64 url 加解密======");
        String urlEncodeData = Base64Util.urlEncodeData(inputStr);
        System.out.println("BASE64 url加密后:" +  urlEncodeData);
        System.out.println("BASE64解密后:" + Base64Util.decodeData(urlEncodeData));
    }

}
