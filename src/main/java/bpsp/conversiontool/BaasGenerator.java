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

        String query_string = "APIKey=" + "74d9a259-a452-45fa-8028-9e89ade25016";
        String requestData = "{\n"
                + "\"EncryptedData\": \"A80E82396FDB6FDB98095806E3638F63\",\n"
                + "\"EncryptedKey\": \"LY7TLLIiFDWJV/ZjK7U67ZYSvwdkgTtfAepXsXqIIvqGKY9coyicEbSXse8m8pQ3RLJUUFwjW4AOIbtHFAQeMhSbHdyak/4iXZ8h4HhXoOdB7irO8f73KV1gleyZlVujceUXogYezR4uZLOXiqUCZTklQbOtjITuxVP4mGDFqFNoWQGuc80uJlAQCPOjODpPv6WDdc4n8DpuYR01pjwfNPUaApxJWpc/XXXvj6Ztm0Tu4AVQMDZmkoS0UdGOnQsoIwjFcXB4kdcb/yPajhis1dZczgFbxsnIs23ozg9EH+TSTVA1AzwChB5gO/blaXqBKm/9R4pkGOGkEsoyv4WxguJGv8z+GqQ4cdmb3aG2c7vMAMCqf8tkYoE50WVL7eqVKyrWDnd21LCG19ICcSEykhcIVCrdD4cF0xxEff1wjj590Gj/8Ltxz1dTqG6mChsHd6Kj3IOfShNU5vpP9/AS7LVLiX3pkdaMmD7Rd+15kHxXTOp3Vet5X370D3JLfmqtrRMgKaci7hy1WR71jJr+M0ORdf6v2HIWk5s8bWZcnX4MpzPYHu0bfGxLOMzT8Vw6Hpul8fGxTxL6dtPRO0KRyvWQXhMl1Lsgu43zcscXIjCUzEL/1cZKeq5mY49qwlLde9rWKEbTyGB1lOISodGKh6O2Qohb0/eifNakEh6CW7s=\"\n"
                + "}";
//        String requestData = "{\"name\":\"Deepak\"}";
        requestData = requestData.replace("\r", "").replace("\n", "").replace(" ", "")
                .replace("\r\n\\", "").replace("\\", "").replace("\"\"{", "{").replace("}\"\"", "}");
        String message = currentTime + "ListPayments" + query_string + requestData;
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
