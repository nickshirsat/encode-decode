/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bpsp.conversiontool;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author admin
 */
public class BaasGenerator {

    public static final String ALGORITHM = "HmacSHA256";

    public static String generate(final String key, final String data) throws NoSuchAlgorithmException, InvalidKeyException {
        if (key == null || data == null) {
            throw new NullPointerException();
        }
        final Mac hMacSHA256 = Mac.getInstance(ALGORITHM);
        byte[] hmacKeyBytes = key.getBytes();
        final SecretKeySpec secretKey = new SecretKeySpec(hmacKeyBytes, ALGORITHM);
        hMacSHA256.init(secretKey);

        return bytesToHex(hMacSHA256.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);

        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        long currentTime = Calendar.getInstance().getTimeInMillis();

        Scanner sc = new Scanner(System.in);
        System.out.printf("Enter Encrypted Data : \n");
        String e_data = sc.nextLine();
        System.out.printf("Enter Encrypted Key : \n");
        String e_key = sc.nextLine();
        System.out.printf("Enter Endpoint : \n");
        String endpoint = sc.nextLine();
        
        String query_string = "APIKey=" + "74d9a259-a452-45fa-8028-9e89ade25016";
        String requestData = "{\n"
                + "\"EncryptedData\": \"" + e_data + "\",\n"
                + "\"EncryptedKey\": \"" + e_key + "\"\n"
                + "}";
//        String requestData = "{\"name\":\"Deepak\"}";
        requestData = requestData.replace("\r", "").replace("\n", "").replace(" ", "")
                .replace("\r\n\\", "").replace("\\", "").replace("\"\"{", "{").replace("}\"\"", "}");
        String message = currentTime + endpoint + query_string + requestData;
        String secetkey = "8126b570-6254-41de-8cbf-8145dc1eed04";

//        System.out.println("plain message = " + message);
        try {
            message = generate(secetkey, message);
            String bassToken = "v1:" + currentTime + ":" + message;
            System.out.println("bassToken = " + bassToken);
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("ex = " + ex);
        } catch (InvalidKeyException ex) {
            System.out.println("ex = " + ex);
//            Logger.getLogger(BaasGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
