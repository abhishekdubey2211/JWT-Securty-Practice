package com.abhi.security.utilities;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class RSA_AES_EncryptionUtil {

    private static final int RSA_KEY_SIZE = 2048;  // RSA Key Size
    private static final int AES_KEY_SIZE = 256;  // AES Key Size
    private static final int IV_SIZE = 16;        // AES IV Size

    // ** Generate and Save RSA Key Pair **
    public static void generateAndSaveKeys() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        saveKeyToFile("private.pem", keyPair.getPrivate().getEncoded(), "PRIVATE");
        saveKeyToFile("public.pem", keyPair.getPublic().getEncoded(), "PUBLIC");

        log.info("RSA Key Pair Generated and Stored!");
    }

    // ** Save RSA Key in PEM Format **
    private static void saveKeyToFile(String filePath, byte[] key, String type) throws IOException {
        String encodedKey = Base64.getEncoder().encodeToString(key);
        String pemFormat = "-----BEGIN " + type + " KEY-----\n" +
                encodedKey.replaceAll("(.{64})", "$1\n") +
                "\n-----END " + type + " KEY-----";

        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(pemFormat.getBytes());
        }
    }

    // ** Load RSA Private Key **
    public static PrivateKey loadPrivateKey(String privateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = extractKeyBytes(privateKeyPath, "PRIVATE");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // ** Load RSA Public Key **
    public static PublicKey loadPublicKey(String publicKeyPath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] keyBytes = extractKeyBytes(publicKeyPath, "PUBLIC");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    // ** Extract Key from PEM File **
    private static byte[] extractKeyBytes(String path, String type) throws IOException {
        String keyData = new String(readFile(path), StandardCharsets.UTF_8)
                .replace("-----BEGIN " + type + " KEY-----", "")
                .replace("-----END " + type + " KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(keyData);
    }

    // ** Read File **
    private static byte[] readFile(String path) throws IOException {
        return new FileInputStream(path).readAllBytes() ;
    }

    // ** Generate AES Key and IV **
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // ** Encrypt AES Key using RSA **
    public static String encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(aesKey.getEncoded()));
    }

    // ** Decrypt AES Key using RSA **
    public static SecretKey decryptAESKey(String encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey));
        return new SecretKeySpec(decryptedKey, "AES");
    }

    // ** AES Encryption **
    public static String encryptData(String data, SecretKey aesKey, IvParameterSpec iv) throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // ** AES Decryption **
    public static String decryptData(String encryptedData, SecretKey aesKey, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // ** Main Method (Testing) **
    public static void main(String[] args) throws Exception {
        generateAndSaveKeys(); // Generate keys (Run only once)

        String originalText = "Hello, Secure World!";
        PublicKey publicKey = loadPublicKey("public.pem");
        PrivateKey privateKey = loadPrivateKey("private.pem");

        // ** Generate AES Key and IV **
        SecretKey aesKey = generateAESKey();
        IvParameterSpec iv = generateIV();

        // ** Encrypt AES Key with RSA Public Key **
        String encryptedAESKey = encryptAESKey(aesKey, publicKey);

        // ** Encrypt Data with AES **
        String encryptedData = encryptData(originalText, aesKey, iv);

        // ** Decrypt AES Key with RSA Private Key **
        SecretKey decryptedAESKey = decryptAESKey(encryptedAESKey, privateKey);

        // ** Decrypt Data with AES **
        String decryptedData = decryptData(encryptedData, decryptedAESKey, iv);

        log.info("\n🔹 Original Text: " + originalText);
        log.info("🔹 Encrypted AES Key (RSA): " + encryptedAESKey);
        log.info("🔹 Encrypted Data (AES): " + encryptedData);
        log.info("🔹 Decrypted Data: " + decryptedData);
    }
}
