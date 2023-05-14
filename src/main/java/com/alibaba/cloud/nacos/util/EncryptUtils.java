package com.alibaba.cloud.nacos.util;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Objects;

/**
 * @author tanghaiyang on 2020-04-16 16:21
 */
public class EncryptUtils {

    private static RSA rsa;
    private EncryptUtils(){
    }

    private static String strParam = "t!h@y#p$w%d";

    private static Cipher cipher;

    public static RSA init(String privateKey, String publicKey){
        if(Objects.isNull(rsa)) {
            rsa = new RSA(privateKey, publicKey);
        }
        return rsa;
    }

    private static IvParameterSpec iv = new IvParameterSpec(strParam.getBytes(StandardCharsets.UTF_8));

    public static String encrypt(String privateKey, String publicKey, String str) {
        RSA rsa = EncryptUtils.init(privateKey, publicKey);
        byte[] encrypt1 = rsa.encrypt(StrUtil.bytes(str, CharsetUtil.CHARSET_UTF_8), KeyType.PublicKey);
        return HexUtil.encodeHexStr(encrypt1);
    }

    public static String decrypt(String privateKey, String publicKey, String str){
        if(StringUtils.isEmpty(str)){
            return null;
        }
        try {
            RSA rsa = EncryptUtils.init(privateKey, publicKey);
            byte[] bytesPassword = rsa.decrypt(str, KeyType.PrivateKey);
            return StringUtils.toEncodedString(bytesPassword, CharsetUtil.CHARSET_UTF_8);
        }catch (Exception e){
            return null;
        }
    }


    /**
     * 对称加密
     */
    public static String desEncrypt(String source) throws Exception {
        DESKeySpec desKeySpec = getDesKeySpec(source);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return byte2hex(
                cipher.doFinal(source.getBytes(StandardCharsets.UTF_8))).toUpperCase();
    }

    /**
     * 对称解密
     */
    public static String desDecrypt(String source) throws Exception {
        byte[] src = hex2byte(source.getBytes());
        DESKeySpec desKeySpec = getDesKeySpec(source);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] retByte = cipher.doFinal(src);
        return new String(retByte);
    }


    public static Key buildKey(String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    ///////////////////////////////////////////////
    private static DESKeySpec getDesKeySpec(String source) throws Exception {
        if (source == null || source.length() == 0){
            return null;
        }
        cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        String strKey = "Passw0rd";
        return new DESKeySpec(strKey.getBytes(StandardCharsets.UTF_8));
    }

    private static String byte2hex(byte[] inStr) {
        String stmp;
        StringBuilder out = new StringBuilder(inStr.length * 2);
        for (byte b : inStr) {
            stmp = Integer.toHexString(b & 0xFF);
            if (stmp.length() == 1) {
                out.append("0").append(stmp);
            } else {
                out.append(stmp);
            }
        }
        return out.toString();
    }

    private static byte[] hex2byte(byte[] b) {
        int size = 2;
        if ((b.length % size) != 0){
            throw new IllegalArgumentException("length is not even number");
        }
        byte[] b2 = new byte[b.length / 2];
        for (int n = 0; n < b.length; n += size) {
            String item = new String(b, n, 2);
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }


}
