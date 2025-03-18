package com.abhi.security.utilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.googlecode.gwt.crypto.bouncycastle.DataLengthException;
import com.googlecode.gwt.crypto.bouncycastle.InvalidCipherTextException;
import com.googlecode.gwt.crypto.client.AESCipher;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class SecurityHandler {

	private final String CRM_AESKEY = "AbhishekDineshKumarDubey22112000";
	private final String CRM_SALT = "@#$abhi&S";
	private static final String AES = "AES";
	private final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
	private final String PBKDF2_HMAC_SHA256 = "PBKDF2WithHmacSHA256";
	private final String PBKDF2_HMAC_SHA1 = "PBKDF2WithHmacSHA1";
	private final String AES_KEY_WRAP = "AESWrap";
	private final int GCM_TAG_LENGTH = 128;
	private final int AES_KEY_SIZE = 256;
	private final int PBKDF2_ITERATIONS = 100000;
	private final int PBKDF2_KEY_LENGTH = 256;
	private final SecureRandom SECURE_RANDOM = new SecureRandom();
	private final int GCM_IV_LENGTH = 16;
	private final String CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	private final SecureRandom RANDOM = new SecureRandom();
	private static AESCipher cipher = null;

	private static final byte[] AES_KEY = new byte[] { (byte) 8, (byte) 12, (byte) 14, (byte) 21, (byte) 6, (byte) 9,
			(byte) 10, (byte) 11, (byte) 21, (byte) 31, (byte) 16, (byte) 17, (byte) 93, (byte) 5, (byte) 54, (byte) 73,
			(byte) 29, (byte) 33, (byte) 65, (byte) 43, (byte) 4, (byte) 68, (byte) 91, (byte) 82, (byte) 14, (byte) 31,
			(byte) 68, (byte) 72, (byte) 41, (byte) 63, (byte) 90, (byte) 81 };

	static void init() {
		cipher = new AESCipher();
		cipher.setKey(AES_KEY);
	}

	public String generateDescryptedSessionId(String strVlaue)
			throws IllegalStateException, DataLengthException, InvalidCipherTextException {
		String decryptedString;
		init();
		decryptedString = cipher.decrypt(strVlaue);
		return decryptedString;
	}

	public String generateEncryptedSessionId(String strVlaue)
			throws IllegalStateException, DataLengthException, InvalidCipherTextException {
		String EncryptedString;
		init();
		EncryptedString = cipher.encrypt(strVlaue);
		return EncryptedString;
	}

	public String generateRandomKey(int size) {
		StringBuilder key = new StringBuilder(size);
		for (int i = 0; i < size; i++) {
			int randomIndex = RANDOM.nextInt(CHARACTERS.length());
			key.append(CHARACTERS.charAt(randomIndex));
		}
		return key.toString();
	}

	private String encryptString(String text, String password, Boolean isCompress)
			throws NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// Convert password to UTF-8 bytes
		byte[] baPwd = password.getBytes(StandardCharsets.UTF_8);

		// Hash the password with SHA-256
		byte[] baPwdHash = MessageDigest.getInstance("SHA-256").digest(baPwd);

		// Convert text to UTF-8 bytes
		byte[] baText = text.getBytes(StandardCharsets.UTF_8);

		if (isCompress) {
			baText = compress(baText);
		}
		byte[] baSalt = CRM_SALT.getBytes(StandardCharsets.US_ASCII);

		// Combine Salt + Text
		byte[] baEncrypted = new byte[baSalt.length + baText.length];
		System.arraycopy(baSalt, 0, baEncrypted, 0, baSalt.length);
		System.arraycopy(baText, 0, baEncrypted, baSalt.length, baText.length);

		// Perform AES Encryption
		baEncrypted = AES_Encrypt(baEncrypted, baPwdHash);
		return Base64.getEncoder().encodeToString(baEncrypted);
	}

	// Method to compress data securely
	private byte[] compress(byte[] data) throws IOException, NoSuchAlgorithmException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

		// Use try-with-resources to ensure that the GZIPOutputStream is closed properly
		try (GZIPOutputStream gzip = new GZIPOutputStream(byteArrayOutputStream)) {
			gzip.write(data);
		}

		// Get the compressed data
		byte[] compressedData = byteArrayOutputStream.toByteArray();

		// Verify data integrity by computing a hash
		byte[] hash = computeHash(data);
		return compressedData;
	}

	private byte[] decompress(byte[] compressedData) throws IOException {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressedData);
		try (GZIPInputStream gzip = new GZIPInputStream(byteArrayInputStream);
				ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
			byte[] buffer = new byte[1024];
			int len;
			while ((len = gzip.read(buffer)) != -1) {
				byteArrayOutputStream.write(buffer, 0, len);
			}
			return byteArrayOutputStream.toByteArray();
		}
	}

	// Decryption method
	private String decryptString(String encryptedText, String password, Boolean isCompressed)
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {

		// Convert password to UTF-8 bytes
		byte[] baPwd = password.getBytes(StandardCharsets.UTF_8);

		// Hash the password with SHA-256
		byte[] baPwdHash = MessageDigest.getInstance("SHA-256").digest(baPwd);

		// Decode the encrypted text from Base64
		byte[] baEncrypted = Base64.getDecoder().decode(encryptedText);

		// Perform AES Decryption
		byte[] decryptedBytes = AES_Decrypt(baEncrypted, baPwdHash);

		// Extract salt and text from the decrypted data
		byte[] saltStr = CRM_SALT.getBytes(StandardCharsets.US_ASCII);
		byte[] baDecryptedText = new byte[decryptedBytes.length - saltStr.length];
		System.arraycopy(decryptedBytes, saltStr.length, baDecryptedText, 0, baDecryptedText.length);

		// Decompress if needed
		if (isCompressed) {
			baDecryptedText = decompress(baDecryptedText);
		}

		return new String(baDecryptedText, StandardCharsets.UTF_8);
	}

	// AES Decryption method
	private byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
		// Derive the key and IV using PBKDF2
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec spec = new PBEKeySpec(new String(passwordBytes).toCharArray(), saltBytes, 1000, 256 + 128);
		SecretKey tmp = factory.generateSecret(spec);

		byte[] keyBytes = Arrays.copyOfRange(tmp.getEncoded(), 0, 32); // AES key
		byte[] ivBytes = Arrays.copyOfRange(tmp.getEncoded(), 32, 48); // IV

		// Initialize AES cipher for decryption
		SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

		// Decrypt the data
		byte[] decryptedBytes = cipher.doFinal(bytesToBeDecrypted);
		return decryptedBytes;
	}

	// Method to verify the integrity of decompressed data
	private boolean verifyDataIntegrity(byte[] originalData, byte[] decompressedData) throws NoSuchAlgorithmException {
		byte[] originalHash = computeHash(originalData);
		byte[] decompressedHash = computeHash(decompressedData);
		return MessageDigest.isEqual(originalHash, decompressedHash);
	}

	private byte[] computeHash(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return digest.digest(data);
	}

	private byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

		// Derive the key and IV using PBKDF2
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec spec = new PBEKeySpec(new String(passwordBytes).toCharArray(), saltBytes, 1000, 256 + 128);
		SecretKey tmp = factory.generateSecret(spec);

		byte[] keyBytes = Arrays.copyOfRange(tmp.getEncoded(), 0, 32); // AES key
		byte[] ivBytes = Arrays.copyOfRange(tmp.getEncoded(), 32, 48); // IV

		// Initialize AES cipher
		SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

		// Encrypt the data
		byte[] encryptedBytes = cipher.doFinal(bytesToBeEncrypted);
		return encryptedBytes;
	}

	// Derive a key from a password
	private String deriveKey(String password, String saltBase64)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] salt = Base64.getDecoder().decode(saltBase64);
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_HMAC_SHA256);
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), AES);
		return Base64.getEncoder().encodeToString(secretKey.getEncoded());
	}

	// Generate a random salt
	private String generateSalt() {
		byte[] salt = new byte[16]; // 128-bit salt
		SECURE_RANDOM.nextBytes(salt);
		return Base64.getEncoder().encodeToString(salt);
	}

	// Generate a random AES key
	private String generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance(AES);
		keyGen.init(AES_KEY_SIZE, SECURE_RANDOM);
		SecretKey secretKey = keyGen.generateKey();
		return Base64.getEncoder().encodeToString(secretKey.getEncoded());
	}

	// Encrypt the AES key with a password-derived key
	private String encryptAESKey(String aesKeyBase64, String wrappingKeyBase64)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
		SecretKey aesKey = new SecretKeySpec(Base64.getDecoder().decode(aesKeyBase64), AES);
		SecretKey wrappingKey = new SecretKeySpec(Base64.getDecoder().decode(wrappingKeyBase64), AES);
		Cipher cipher = Cipher.getInstance(AES_KEY_WRAP);
		cipher.init(Cipher.WRAP_MODE, wrappingKey);
		byte[] wrappedKey = cipher.wrap(aesKey);
		return Base64.getEncoder().encodeToString(wrappedKey);
	}

	// Decrypt the AES key with a password-derived key
	private String decryptAESKey(String wrappedKeyBase64, String wrappingKeyBase64) throws Exception {
		SecretKey wrappingKey = new SecretKeySpec(Base64.getDecoder().decode(wrappingKeyBase64), AES);
		Cipher cipher = Cipher.getInstance(AES_KEY_WRAP);
		cipher.init(Cipher.UNWRAP_MODE, wrappingKey);
		byte[] decodedKey = Base64.getDecoder().decode(wrappedKeyBase64);
		SecretKey secretKey = (SecretKey) cipher.unwrap(decodedKey, AES, Cipher.SECRET_KEY);
		return Base64.getEncoder().encodeToString(secretKey.getEncoded());
	}

	// Encrypt a plaintext string
	private String encrypt(String plaintext, String keyBase64) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(keyBase64), AES);
		Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
		byte[] iv = new byte[GCM_IV_LENGTH];
		SECURE_RANDOM.nextBytes(iv); // Securely generate the IV
		GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
		byte[] encryptedText = cipher.doFinal(plaintext.getBytes());
		byte[] encryptedTextWithIv = new byte[GCM_IV_LENGTH + encryptedText.length];
		System.arraycopy(iv, 0, encryptedTextWithIv, 0, GCM_IV_LENGTH);
		System.arraycopy(encryptedText, 0, encryptedTextWithIv, GCM_IV_LENGTH, encryptedText.length);
		return Base64.getEncoder().encodeToString(encryptedTextWithIv);
	}

	private String decrypt(String encryptedTextBase64, String keyBase64)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] encryptedTextWithIv = Base64.getDecoder().decode(encryptedTextBase64);

		// Extract the IV
		byte[] iv = new byte[GCM_IV_LENGTH];
		System.arraycopy(encryptedTextWithIv, 0, iv, 0, GCM_IV_LENGTH);

		// Extract the encrypted text (excluding the IV part)
		byte[] encryptedText = new byte[encryptedTextWithIv.length - GCM_IV_LENGTH];
		System.arraycopy(encryptedTextWithIv, GCM_IV_LENGTH, encryptedText, 0, encryptedText.length);

		// Decrypt
		SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(keyBase64), AES);
		Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
		GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
		cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

		byte[] decryptedText = cipher.doFinal(encryptedText);
		return new String(decryptedText);
	}

	private String bytesToHex(byte[] bytes) {
		StringBuilder hexString = new StringBuilder();
		for (byte b : bytes) {
			String hex = Integer.toHexString(0xff & b);
			if (hex.length() == 1)
				hexString.append('0');
			hexString.append(hex);
		}
		return hexString.toString();
	}

	public Map<String, String> derivedKeyEncryption(String data) throws Exception {
		// Generate a salt
		String salt = generateSalt();

		// Derive a key from the password and salt
		String derivedKey = deriveKey(CRM_AESKEY, salt);

		// Encrypt the plaintext using the derived key
		String encryptedText = encrypt(data, derivedKey);
		Map<String, String> encryptionData = new HashMap<>();
		encryptionData.put("derivedkey", derivedKey);
		encryptionData.put("encrypteddata", encryptedText);
		return encryptionData;
	}

	public String derivedKeyDecryption(String encryptedData, String derivedKey) throws Exception {
		return decrypt(encryptedData, derivedKey);
	}

	public Map<String, String> secureAESEncryption(String data) throws Exception {
		String aesKey = generateAESKey();
		String salt = generateSalt();

		// Derive key from password and salt
		String derivedKey = deriveKey(CRM_AESKEY, salt);

		// Encrypt AES key with the derived key
		String wrappedKey = encryptAESKey(aesKey, derivedKey);

		// Decrypt AES key with the derived key
		String unwrappedKey = decryptAESKey(wrappedKey, derivedKey);

		// Encrypt and decrypt a sample text
		String encrypteddata = encrypt(data, aesKey);
		Map<String, String> encryptionData = new HashMap<>();
		encryptionData.put("aesKey", aesKey);
		encryptionData.put("encrypteddata", encrypteddata);
		return encryptionData;
	}

	public String secureAESDescryption(String encryptedData, String AESKEY) throws Exception {
		return decrypt(encryptedData, AESKEY);
	}

	public String AESencrypt(String originalData)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		return encryptString(originalData, CRM_AESKEY, true);
	}

	public String AESdecrypt(String encryptedData)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		return decryptString(encryptedData, CRM_AESKEY, true);
	}

	// Generate an MD5 hash from a string
	public String getMD5Hash(String input) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] hashBytes = md.digest(input.getBytes());
		return bytesToHex(hashBytes);
	}

	// Verify if the plaintext password matches the hashed password
	public boolean verifyPassword(String plaintext, String hashed) throws NoSuchAlgorithmException {
		String hashedInput = getMD5Hash(plaintext);
		return hashedInput.equalsIgnoreCase(hashed);
	}

	// Generate a Cipher transformation based on whether it's for encryption or
	// decryption
	private  Cipher getCipher(boolean encrypting, String password, String salt) throws Exception {
		byte[] iv = new byte[16];
		SecretKeySpec keySpec = generateKey(password, salt);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
		return cipher;
	}

	// Derive AES key using PBKDF2 and SHA-1
	private  SecretKeySpec generateKey(String password, String salt) throws Exception {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 65536, 256);
		SecretKey secretKey = factory.generateSecret(spec);
		return new SecretKeySpec(secretKey.getEncoded(), "AES");
	}

	// Encrypt the raw string and encode it in Base64
	public  String encryptAndEncode(String raw, String password, String salt) throws Exception {
		Cipher cipher = getCipher(true, password, salt);
		byte[] bytes = raw.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedBytes = cipher.doFinal(bytes);
		return Base64.getEncoder().encodeToString(encryptedBytes); // Return Base64 encoded string
	}

	// Decrypt the Base64 encoded string
	public  String decryptAndDecode(String encryptedText, String password, String salt) throws Exception {
		Cipher cipher = getCipher(false, password, salt);
		byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
		byte[] decryptedBytes = cipher.doFinal(decodedBytes);
		return new String(decryptedBytes, StandardCharsets.UTF_8); // Return decrypted string
	}

//	public static  void main(String[] args) {
//		SecurityHandler handler = new SecurityHandler();
//		Map<String, String> encryptionData = new HashMap<>();
//		Map<String, String> encryptionData2 = new HashMap<>();
//
//		String originalText = "Abhishek Dinesh Kumar Dubey";
//		try {
//			System.out.println("Original Text: " + originalText);
//
//			// Encrypt
//			String encryptedText = handler.AESencrypt(originalText);
//			System.out.println("Encrypted Text: " + encryptedText);
//
//			// Decrypt
//			String decryptedText = handler.AESdecrypt(encryptedText);
//			System.out.println("Decrypted Text: " + decryptedText);
//
//			encryptionData = handler.derivedKeyEncryption(originalText);
//			System.out.println("derivedKeyEncryption Text: " + encryptionData);
//
//			String derivedDecryptedText = handler.derivedKeyDecryption(encryptionData.get("encrypteddata"),
//					encryptionData.get("derivedkey"));
//			System.out.println("derivedKeyDecryption Text: " + derivedDecryptedText);
//
//			encryptionData2 = handler.secureAESEncryption(originalText);
//			System.out.println("secureAESEncryption Text: " + encryptionData2);
//
//			String securedDecryptedText = handler.derivedKeyDecryption(encryptionData2.get("encrypteddata"),
//					encryptionData2.get("aesKey"));
//			System.out.println("securedDecryptedText Text: " + securedDecryptedText);
//
//			String hashedPassword = handler.getMD5Hash(originalText);
//			System.out.println("hashedPassword : " + hashedPassword);
//
//			// Verifying passwords
//			boolean match = handler.verifyPassword(originalText, hashedPassword);
//			System.out.println("Password match: " + (match ? "Yes" : "No"));
//
//			boolean mismatch = handler.verifyPassword(originalText, hashedPassword);
//			System.out.println("Password mismatch: " + (mismatch ? "Yes" : "No"));
//
//			String encryptedSessionid = handler.generateEncryptedSessionId(originalText);
//			System.out.println("generateEncryptedSessionId Text: " + encryptedSessionid);
//
//			String decryptedSessionId = handler.generateDescryptedSessionId(encryptedSessionid);
//			System.out.println("generateDescryptedSessionId Text: " + decryptedSessionId);
//
//			String encryptedString = handler.encryptAndEncode(originalText,
//					"GcaCWxn2prfNFW0eEGpNC9=", "@#$abhi&S");
//			System.out.println("Encrypted: " + encryptedString);
//
//			String decryptedString = handler.decryptAndDecode(encryptedString,
//					"GcaCWxn2prfNFW0eEGpNC9=", "@#$abhi&S");
//			System.out.println("Decrypted: " + decryptedString);
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//	}
}