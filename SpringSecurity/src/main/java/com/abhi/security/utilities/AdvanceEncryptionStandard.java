package com.abhi.security.utilities;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class AdvanceEncryptionStandard {
    private static final Logger logger = LoggerFactory.getLogger(AdvanceEncryptionStandard.class);
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;
    private static final int SALT_SIZE = 16;
    private String key = "AbhishekDineshKumarDubey22112000";
    private SecretKey encryptionKey;

    public AdvanceEncryptionStandard() {
        if (key.length() != KEY_SIZE / 8) {
            throw new IllegalArgumentException("Invalid key length. Key must be 32 bytes for AES-256.");
        }
        this.encryptionKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
    }

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_SIZE];
        byte[] salt = new byte[SALT_SIZE];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        secureRandom.nextBytes(salt);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivSpec);
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        
        byte[] finalData = new byte[IV_SIZE + SALT_SIZE + encryptedData.length];
        System.arraycopy(iv, 0, finalData, 0, IV_SIZE);
        System.arraycopy(salt, 0, finalData, IV_SIZE, SALT_SIZE);
        System.arraycopy(encryptedData, 0, finalData, IV_SIZE + SALT_SIZE, encryptedData.length);
        
        return Base64.getEncoder().encodeToString(finalData);
    }

    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] encryptedIvSaltData = Base64.getDecoder().decode(encryptedData);
        byte[] iv = new byte[IV_SIZE];
        byte[] salt = new byte[SALT_SIZE];
        
        System.arraycopy(encryptedIvSaltData, 0, iv, 0, IV_SIZE);
        System.arraycopy(encryptedIvSaltData, IV_SIZE, salt, 0, SALT_SIZE);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        byte[] encryptedBytes = new byte[encryptedIvSaltData.length - IV_SIZE - SALT_SIZE];
        System.arraycopy(encryptedIvSaltData, IV_SIZE + SALT_SIZE, encryptedBytes, 0, encryptedBytes.length);
        
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, ivSpec);
        byte[] decryptedData = cipher.doFinal(encryptedBytes);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public String decodeEncryptedKey(String encryptedJwtToken) {
        try {
            return decrypt(encryptedJwtToken);
        } catch (Exception e) {
            logger.error("Decryption error: {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public String encryptData(String data) {
        try {
            return encrypt(data);
        } catch (Exception e) {
            logger.error("Encryption error: {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        AdvanceEncryptionStandard aes = new AdvanceEncryptionStandard();
        String enc = aes.encrypt("Abhi");
        String decrypted = aes.decrypt(enc);
        System.out.print("encrypt :: " + enc + " || decrypted :: " + decrypted);
    }
}
