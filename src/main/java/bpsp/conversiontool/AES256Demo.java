/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bpsp.conversiontool;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author admin
 */
public class AES256Demo {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
//    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    private static IvParameterSpec generateIV(String key) {
        // Generating IV.
        String ivStr = key.substring(0, 16);
        System.out.println("IV = " + ivStr);
        return new IvParameterSpec(ivStr.getBytes());
    }

    public static String generateRandomKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        SecretKey secret = gen.generateKey();
        return Base64.getEncoder().encodeToString(bytesToHex(secret.getEncoded()).getBytes()).substring(0, 32);
//        return Base64.getEncoder().encodeToString(secret.getEncoded());
    }

    public static String encrypt(String text, String key) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

//        text = text.replace("\r", "").replace("\n", "").replace(" ", "")
//                .replace("\r\n\\", "").replace("\\", "").replace("\"\"{", "{").replace("}\"\"", "}");
//        byte[] keyBytes = key.getEncoded();
//        String ivStr = Base64.getEncoder().encodeToString(keyBytes).substring(0, 16);
        //Create IvParameterSpec
        IvParameterSpec iv = generateIV(key);
        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

        //Perform Encryption
        byte[] cipherText = cipher.doFinal(text.getBytes());

//        return Base64.getEncoder().encodeToString(cipherText);
        return bytesToHex(cipherText).toUpperCase();
    }

    public static String decrypt(String cipherText, String key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException {

//        String ivStr = Base64.getEncoder().encodeToString(key).substring(0, 16);
        IvParameterSpec iv = generateIV(key);

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        byte[] plainText = cipher.doFinal(hexStringToByteArray(cipherText));
        return new String(plainText);
    }

    public static void main(String[] args) throws IOException {

        try {
//            String name = "{}";
//
//            System.out.println("Plan text = " + name);
//            String key = generateRandomKey();
//
//            System.out.println("plain text key = " + key);
//
//            String encryptedKey = RSAUtil.encrypt(key.getBytes(), "");
//            System.out.println("encryptedKey = " + encryptedKey);
//            String encryptedText = encrypt(name, key);
//            System.out.println("encryptedText = " + encryptedText);
            String encryptedKey = "bH6kNEtxGALXP8JLqzW1wcdkIwbcGCNIpG/5RE+1ikta5poUhJXCcvHIa7uqGm001UUCOud8/96TVZmZtr7eiRJGYToCOdXq1JawFw5aDPQlzdmI/aAMwp598vt2KMorrInpX7SA/CQE0/s0l7d+iIvwIKp6GZUEGA6/ctmg+oPckhTWVXf3yXZIPy1bCpkPDZh/29+xfuc5whHIrUf6pUiNlsfjcqvmrz7frgIjDwasJdQbcU8KZ0sDUOCG1bpHR/v1m10DVpHuWTUl+JeCsWfsrdfXv36KH0GWczY18WiiLXQh8IZ77P37Ub1i6ztUDp0kLVa9/DzZtg4u5CG59FRSSWuX2yE2XZMMNdipoLUrC9cJAWRWIRmoovyUoEZ2pl+3d+0xzHkWdzC1UDjJqyy0umj06th6MpvDHTMevCkRqkAGtTGB34CPJ8YiPAkIeoS1qdt5VLpLCNRp6dXSMGT1jOaHDkPsAQDSyEAvIoXwEJsxhoMC4esNTG7OhOWtVY1BUfI41LXvtmBsZYwlQ1o5U9v9OfPdKEUaiFiAJMPPhuatViaWT6bYXxqQZks9+BVN+MIZ0h/GLQFittuWb4Sq5pJS6L4h0+VOr/G97h+bZ90aes0VPHIuzVXPeowDUEUbQtkM30VCIUtrfzb0bLnt8ydSJUks6UugizHBO6Y=";
            String encryptedText = "CE274494A67FD96798BFC5B556AFEF55ACC8CEE3CE08DE1906B3C0B7C1217DF090EFFB1851C08993733D10B7D3DC467E";
            System.out.println("decrypt key");
            byte[] decryptKey = RSAUtil.decrypt(encryptedKey);
            String key1 = new String(decryptKey);
//            String key1 = bytesToHex(Base64.getDecoder().decode(decryptKey));
            System.out.println("decrypted Key = " + key1);
            String decryptedText = decrypt(encryptedText, key1);
            System.out.println("decryptedText = " + decryptedText);
//            System.out.println("public = " + publicKey.length());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AES256Demo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(AES256Demo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(AES256Demo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(AES256Demo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(AES256Demo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(AES256Demo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(AES256Demo.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);

        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        System.out.println("data = " + data);
        return data;
    }
}
