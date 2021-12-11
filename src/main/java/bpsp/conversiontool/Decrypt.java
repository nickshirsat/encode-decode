package bpsp.conversiontool;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;
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


public class Decrypt {


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
        	Scanner sc = new Scanner(System.in);
//            String name = "{\n"
//            		+ "        \"filter\": {\n"
//            		+ "                \"baas_buyer_xpress_id\": \"LNIT000001\",\n"
//            		+ "                \"bpsp_buyer_code\": \"EMI50113\",\n"
//            		+ "                \"baas_supplier_xpress_id\": \"SCIF000001\",\n"
//            		+ "                \"bpsp_suplier_code\": \"AIRB51222\",\n"
//            		+ "                \"created_date_from\": \"\",\n"
//            		+ "                \"created_date_to\": \"\"\n"
//            		+ "        },\n"
//            		+ "        \"pagination_index\": 1,\n"
//            		+ "        \"limit\": 10\n"
//            		+ "}";
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
        	System.out.println("Enter Encrypted Response Data : ");
        	String encryptedText = sc.nextLine();
        	System.out.println("Enter Encrypted Response Key : ");
            String encryptedKey = sc.nextLine();
            System.out.println("decrypt key");
            byte[] decryptKey = RSAUtil.decrypt(encryptedKey);
            String key1 = new String(decryptKey);
//            String key1 = bytesToHex(Base64.getDecoder().decode(decryptKey));
            System.out.println("decrypted Key = " + key1);
            String decryptedText = decrypt(encryptedText, key1);
            System.out.println("decryptedText = " + decryptedText);
//            System.out.println("public = " + publicKey.length());
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
