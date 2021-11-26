/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bpsp.conversiontool;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class RSAUtil {
	

    static String publicKeyPath = "D:\\RSA\\New folder\\cacert.csr";
    static String privateKeyPath = "D:\\visa\\keys\\bpsp_private_key.pem";
    static String visaPublicKeyPath = "D:\\visa\\keys\\VISA_public_key.cer";
//    private static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String ALGORITHM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";

    public static PublicKey getPublicKey(String publicKeyPath1) {
        PublicKey publicKey = null;
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            X509Certificate cer = (X509Certificate) fact.generateCertificate(new FileInputStream(visaPublicKeyPath));
            publicKey = cer.getPublicKey();
//            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
//            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
//        } catch (NoSuchAlgorithmException ex) {
//            Logger.getLogger(RSAUtil.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (InvalidKeySpecException ex) {
//            Logger.getLogger(RSAUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(RSAUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(RSAUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey() throws IOException {
        PrivateKey privateKey = null;
        String key = new String(Files.readAllBytes(new File(privateKeyPath).toPath()), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyPEM));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static String encrypt(byte[] data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return Base64.getEncoder().encodeToString(cipher.doFinal(data));
        //        return bytesToHex(cipher.doFinal(data));

    }

    private static byte[] decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//       Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
//OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT);
//oaepFromInit.init(Cipher.DECRYPT_MODE, privkey, oaepParams);
//byte[] pt = oaepFromInit.doFinal(ct);
//System.out.println(new String(pt, StandardCharsets.UTF_8));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(String data) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey());
    }

//    private static final String SECRET_KEY = "8126b570-6254-41de-8cbf-8145dc1eed04";
    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IOException {
//        try {
//        PublicKey key = getPublicKey("");
//        PrivateKey prKey = getPrivateKey();
//        System.out.println(key);
//        System.out.println(prKey);
//        System.out.println(SECRET_KEY);
//            String encryptedString = encrypt(SECRET_KEY.getBytes(), publicKeyPath);
//            System.out.println(encryptedString);
//            String decryptedString = new String(RSAUtil.decrypt(encryptedString));
//            System.out.println(decryptedString);
//        } catch (NoSuchAlgorithmException e) {
//            System.err.println(e.getMessage());
//        } catch (IOException ex) {
//            Logger.getLogger(RSAUtil.class.getName()).log(Level.SEVERE, null, ex);
//        }

    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);

        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}
