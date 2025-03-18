package com.abhi.security.utilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@Component
public class EncryptionUtil {

	public static final String CRM_AESKEY = "AbhishekDineshKumarDubey22112000";
	private static final String CRM_AESIV = "Q3frLG6FPQIl5cXe3W7I5w==";
	private static final String CRM_SALT = "@#$abhi&L";
	private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private static final String CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	private static final SecureRandom RANDOM = new SecureRandom();

	public String encryptString(String text, boolean compressText) {
		try {
			byte[] passwordHash;

			passwordHash = hashPassword(CRM_AESKEY);

			byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
			if (compressText) {
				textBytes = compress(textBytes);
			}
			byte[] saltedText = appendSalt(textBytes);
			byte[] encryptedBytes = AES_Encrypt(saltedText, passwordHash);
			return Base64.getEncoder().encodeToString(encryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public String decryptString(String encryptedText, boolean isCompressed) throws Exception {
		byte[] passwordHash = hashPassword(CRM_AESKEY);
		byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
		byte[] decryptedBytes = AES_Decrypt(encryptedBytes, passwordHash);
		byte[] salt = CRM_SALT.getBytes(StandardCharsets.US_ASCII);
		byte[] originalTextBytes = extractSalt(decryptedBytes, salt.length);
		if (isCompressed) {
			originalTextBytes = decompress(originalTextBytes);
		}
		return new String(originalTextBytes, StandardCharsets.UTF_8);
	}

	private byte[] hashPassword(String password) throws NoSuchAlgorithmException {
		return MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
	}

	private byte[] AES_Encrypt(byte[] data, byte[] key) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, "AES");
		IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(CRM_AESIV));
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
		return cipher.doFinal(data);
	}

	private byte[] AES_Decrypt(byte[] data, byte[] key) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, "AES");
		IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(CRM_AESIV));
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
		return cipher.doFinal(data);
	}

	private byte[] appendSalt(byte[] data) {
		byte[] salt = CRM_SALT.getBytes(StandardCharsets.US_ASCII);
		byte[] saltedData = new byte[salt.length + data.length];
		System.arraycopy(salt, 0, saltedData, 0, salt.length);
		System.arraycopy(data, 0, saltedData, salt.length, data.length);
		return saltedData;
	}

	private byte[] extractSalt(byte[] data, int saltLength) {
		byte[] originalData = new byte[data.length - saltLength];
		System.arraycopy(data, saltLength, originalData, 0, originalData.length);
		return originalData;
	}

	private byte[] compress(byte[] data) throws IOException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		try (GZIPOutputStream gzip = new GZIPOutputStream(byteArrayOutputStream)) {
			gzip.write(data);
		}
		return byteArrayOutputStream.toByteArray();
	}

	private byte[] decompress(byte[] data) throws IOException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(data))) {
			byte[] buffer = new byte[1024];
			int len;
			while ((len = gzip.read(buffer)) != -1) {
				byteArrayOutputStream.write(buffer, 0, len);
			}
		}
		return byteArrayOutputStream.toByteArray();
	}

	public static String generateRandomKey(int size) {
		StringBuilder key = new StringBuilder(size);
		for (int i = 0; i < size; i++) {
			int randomIndex = RANDOM.nextInt(CHARACTERS.length());
			key.append(CHARACTERS.charAt(randomIndex));
		}
		return key.toString();
	}
}