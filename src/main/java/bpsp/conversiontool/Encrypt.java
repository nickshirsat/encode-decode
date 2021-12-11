/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bpsp.conversiontool;

import java.io.IOException;
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
public class Encrypt {

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
            String name = "{\r\n" + 
            		"	\"request_id\": \"33387644224\",\r\n" + 
            		"	\"baas_token_id\": \"1341122196819\"\r\n" + 
            		"}";

            System.out.println("Plan text = " + name);
            String key = generateRandomKey();

            System.out.println("plain text key = " + key);

            String encryptedKey = RSAUtil.encrypt(key.getBytes(), "");
            System.out.println("encryptedKey = " + encryptedKey);
            String encryptedText = encrypt(name, key);
            System.out.println("encryptedText = " + encryptedText);
//            String encryptedKey = "QcWAXzBn8x6FkcQKzW8Nezs5MONpWw+CcBtRhFmN0Iy4kh0cXctPiDw/IvEq02307igMFaThzRwbkub1FPKMquiZ0OEXbBVd6jiDaPNG90WtzpamJJxJb3Vq/0pJv1VmTFHXhx7xy3KTekJXJSxp4MxnS8J8mlUBy24ugtqQ8wkzU+EWZxSbGM7xsKAfZs/INV8IcvqM9XSKLZm4KI9XMyBChiAQG+SnYLsH6HsF3ACusnINYWAeumQ9goBtJ6vTrFQTtKOILHJnhYzeMifbXTRg3GcUAbdNa80UODdM5TLITncUklUGJhJgfK77LJk21HUdfJBL0MUss9Rf8jBANVjEeguHIJmoa+bMzTpv6SrGr31MbZAj3j1S/9BNdRtuvnIkxJ9X2f1n/b3uZHfXMw18VNNfJMomz1wGnOATcHdEdERWYNe8y6pRSJXRGqhcnAD80BDghkbFhvNyUa0RRCAkgLUhyPh9NtwoWFJ01uyhbovPY1GDoUi4ERxKW90sREcL84bJU+iS163HW+N5XJCez8Zhd4OBxug3Kfmu2EVB66KzXPAah70onuh8AtbepqLopnNITX9uC9ADXYgA6vUpgOzFcXUWk00FxKN1YSwfW3vyJ1lPDhrQz4feAA8qCsyHo5BIQ2jcorj9WIAholJUMjfNLpBfNGugPT3FjO4=";
//            String encryptedText = "333891CD0D445807808D06DDD5FBF39C38B415616997CCD890B28A337ED29275F6CE8E8F3756970EDDD1B1DB96F5230CB9D00B28D8978DB0614199F97538312F9D3AB777D896813277C14FBF72BAF4562AAACB05758B9972DAAE0D93721CA94F50F6AB8B1604152FCD48647B3ABA3280B14E23623B675CB624776EBB44E4B86F0D17EE3805884803F0B0E23C9EDA1E0845926BEF024DF168E3294CFEA0F0AD39D97174CE5A36A1DAC46729B6930E0CFF7467C9EE938A2404993D8253BA1FB390628FACC6B4D10BA3B23E84D87EA25470E9E3820CA82C216E9A4977FD4DDD382C3BC56014DF6FED8FF9DF2A8120CC9A9FF4FFDA1072049B0FD0CD148F3F6A30494898247B470E6FBD42B130F3AFA2819857B7CA16D80F66FADF06C415843F9C115FF414CD277B390ECF10ACFF3CF3BC01DA11D15B84721235D7349966E4A3D4EAC8D3DA378060F8A5D92383EBA1E847695D653C57B12CEB3F0BBD5ADC54923B39024CA611BF7B83CE215F77D07FE22862762D97858B375FA7462B89CDBAF30295D47A0505FC5376E7F1CED4807B17D9221CB977F13632EF40CD71D68FABBC0431930D070D2B4AE33A002F99B66D309B3612DF3BCE397494B68721093E151BC409C2720138990096E146B0218B0AC9B8E7968A413B0D78048F19F3DF26CF6E066A17497217AAE0CF8B9AC34A16EF721ACF19745F1E7051BFF4272B9DFB6E9D90260ADD4CCDF0F2CBBFABCF96F0E94A728043FC2379930505A4BB946F216F001384DFE7D594C9A4E5D46B89E2B60C46488B43A41F11C9142A1DF5CE90C0285B01CDD5DE0F479B8A9E89752577D28C4FE10EC88207E2F03C1D205D9A515E380DB010FB598E35DBF67DE92E45DCA321ED476AAF0564AA54A97738802B3D4E8377A4F1C726E9106B523F50186D6AB4674CF207601BD2014E121228BFAAE63D33F06286D5FE20AC2CE33737B5E9B8E46066A67E270F6DECE04BACD1B6020404261A25C97B9649BAE0E023CAB2E04A30AA3CA04C7C2F91F6104F577F3A599DF973BD4D9A1CA58B37D237CC1C1230A216004013A16F30E271C71B8DD6A82DC1E910FDB75239F72AC422CB251C044406E1816903F2854BAFECB2EC4DA7DE80EF7672C4BDE31B03E8D9FC1043ABD76A59D964824873EBC2C95254B482278E9E9CDE6967E9AD7452AF45473D0CB7D936DF087D1F3B3ABE893965283928E2AFF6B98372E750DD11F86B7C4AE434C6B29ABD74C1D43C7F";
//            System.out.println("decrypt key");
//            byte[] decryptKey = RSAUtil.decrypt(encryptedKey);
//            String key1 = new String(decryptKey);
////            String key1 = bytesToHex(Base64.getDecoder().decode(decryptKey));
//            System.out.println("decrypted Key = " + key1);
//            String decryptedText = decrypt(encryptedText, key1);
//            System.out.println("decryptedText = " + decryptedText);
////            System.out.println("public = " + publicKey.length());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
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
