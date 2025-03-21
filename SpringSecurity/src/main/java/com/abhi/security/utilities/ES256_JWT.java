package com.abhi.security.utilities;


import io.jsonwebtoken.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import java.util.Base64;

@Slf4j
public class ES256_JWT {

    private static final long EXPIRATION_TIME = 60 * 60; // 1 hour in seconds
    private static final long REFRESH_EXPIRATION_TIME = 24 * 60 * 60; // 24 hours in seconds
    private static final String PRIVATE_KEY_FILE = "ec_private_key.pem";
    private static final String PUBLIC_KEY_FILE = "ec_public_key.pem";

    private static KeyPair keyPair;

    static {
        try {
            keyPair = loadOrGenerateKeyPair();
        } catch (Exception e) {
            log.error("Error initializing key pair: {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads existing key pair or generates a new one if not found.
     */
    private static KeyPair loadOrGenerateKeyPair() throws Exception {
        if (Files.exists(Paths.get(PRIVATE_KEY_FILE)) && Files.exists(Paths.get(PUBLIC_KEY_FILE))) {
            return loadKeyPair();
        } else {
            return generateAndStoreKeyPair();
        }
    }

    /**
     * Generates an EC key pair and stores it in PEM files.
     */
    private static KeyPair generateAndStoreKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1")); //
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Convert to PEM format
        String publicKeyPEM = convertPublicKeyToPEM((ECPublicKey) keyPair.getPublic());
        String privateKeyPEM = convertPrivateKeyToPEM((ECPrivateKey) keyPair.getPrivate());

        // Save to files
        saveToFile(PUBLIC_KEY_FILE, publicKeyPEM);
        saveToFile(PRIVATE_KEY_FILE, privateKeyPEM);

        log.info("New EC key pair generated and stored in PEM files.");
        return keyPair;
    }

    /**
     * Loads the key pair from PEM files.
     */
    private static KeyPair loadKeyPair() throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE));

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(extractPemContent(privateKeyBytes))));
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(extractPemContent(publicKeyBytes))));

        log.info("EC key pair loaded from PEM files.");
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Generates a JWT token.
     */
    public String generateToken(Map<String, Object> claims, String subject, String tokenType) {
        long expirationTime = tokenType.equalsIgnoreCase("REFRESH") ? REFRESH_EXPIRATION_TIME : EXPIRATION_TIME;
        claims = new HashMap<>(claims);
        claims.put("token_type", tokenType + "_TOKEN");

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(expirationTime)))
                .signWith(keyPair.getPrivate(), Jwts.SIG.ES256)
                .compact();
    }

    public boolean validateJwtToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (JwtException e) {
            log.error("Invalid token: {}", e.getMessage());
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        return getClaims(token).getSubject();
    }

    public String getClaimsAsJson(String token) {
        return new Gson().toJson(getClaims(token));
    }

    public boolean isTokenValid(String token) {
        return getClaims(token).getExpiration().after(new Date());
    }

    public boolean hasRole(String token, String role) {
        List<String> roles = (List<String>) getClaims(token).get("roles");
        return roles != null && roles.contains(role);
    }

    public Object getClaimFromToken(String token, String claimKey) {
        return getClaims(token).get(claimKey);
    }

    public String refreshToken(String token) {
        Claims claims = getClaims(token);
        return generateToken(claims, claims.getSubject(), "REFRESH");
    }

    public Date getTokenExpiry(String token) {
        return getClaims(token).getExpiration();
    }

    public Map<String, Object> getAllTokenDetails(String token) {
        Claims claims = getClaims(token);
        Map<String, Object> tokenDetails = new HashMap<>();
        tokenDetails.put("subject", claims.getSubject());
        tokenDetails.put("issuedAt", claims.getIssuedAt());
        tokenDetails.put("expiration", claims.getExpiration());
        tokenDetails.put("claims", claims);
        return tokenDetails;
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Converts an EC public key to PEM format.
     */
    private static String convertPublicKeyToPEM(ECPublicKey publicKey) {
        return "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()) +
                "\n-----END PUBLIC KEY-----\n";
    }

    /**
     * Converts an EC private key to PEM format.
     */
    private static String convertPrivateKeyToPEM(ECPrivateKey privateKey) {
        return "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()) +
                "\n-----END PRIVATE KEY-----\n";
    }

    /**
     * Saves a string to a file.
     */
    private static void saveToFile(String fileName, String content) throws IOException {
        Files.write(Paths.get(fileName), content.getBytes());
    }

    /**
     * Extracts the base64-encoded content from a PEM file.
     */
    private static String extractPemContent(byte[] pemFileContent) {
        String pemString = new String(pemFileContent);
        return pemString.replaceAll("-----BEGIN .*-----", "")
                .replaceAll("-----END .*-----", "")
                .replaceAll("\\s+", "");
    }

    public static void main(String[] args) {
        ES256_JWT jwtUtility = new ES256_JWT();

        String subject = "testUser";
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", List.of("USER", "ADMIN"));

        String token = jwtUtility.generateToken(claims, subject, "LOGIN");
        log.info("Generated Token: {}", token);
        log.info("Validate Token: {}", jwtUtility.validateJwtToken(token));
        log.info("Username from Token: {}", jwtUtility.getUsernameFromToken(token));
        log.info("Claims as JSON: {}", jwtUtility.getClaimsAsJson(token));
        log.info("Is Token Valid? {}", jwtUtility.isTokenValid(token));
        log.info("Has ADMIN Role? {}", jwtUtility.hasRole(token, "ADMIN"));
        log.info("JWT Token Expiry: {}", jwtUtility.getTokenExpiry(token));

        String refreshedToken = jwtUtility.refreshToken(token);
        log.info("Refreshed Token: {}", refreshedToken);
        log.info("Is Refreshed Token Valid? {}", jwtUtility.isTokenValid(refreshedToken));
    }
}
