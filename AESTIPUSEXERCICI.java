package aestipusexercici;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESTIPUSEXERCICI {

    public static void main(String[] args) throws Exception {
        String originalText = "TEXT TEST TEXT TEST";

        //Generem la clau
        SecretKey secretKey = generateKey(128);

        //Xifrat i desxifrat en mode ECB
        String encryptedECB = encryptECB(originalText, secretKey);
        String decryptedECB = decryptECB(encryptedECB, secretKey);

        System.out.println("Text original: " + originalText);
        System.out.println("Text xifrat (ECB): " + encryptedECB);
        System.out.println("Text desxifrat (ECB): " + decryptedECB);

        //Xifrat i desxifrat en mode CBC
        String encryptedCBC = encryptCBC(originalText, secretKey);
        String decryptedCBC = decryptCBC(encryptedCBC, secretKey);

        System.out.println("Text xifrat (CBC): " + encryptedCBC);
        System.out.println("Text desxifrat (CBC): " + decryptedCBC);
    }

    //Metode per generar una clau AES
    private static SecretKey generateKey(int n) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(n);
        return keyGen.generateKey();
    }

    //Metode per xifrar en mode ECB
    private static String encryptECB(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    //Metode per desxifrar en mode ECB
    private static String decryptECB(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    //Metode per xifrar en mode CBC
    private static String encryptCBC(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        // Retornem IV + xifrat
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    //Metode per desxifrar en mode CBC
    private static String decryptCBC(String encryptedData, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedData);
        byte[] iv = new byte[16]; // 16 bytes per AES
        byte[] encryptedBytes = new byte[combined.length - iv.length];

        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}
