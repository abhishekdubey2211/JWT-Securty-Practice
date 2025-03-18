package com.abhi.security.utilities;

import io.jsonwebtoken.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RSA256_JWT {

    private static final String PRIVATE_KEY_FILE = "private.pem";
    private static final String PUBLIC_KEY_FILE = "public.pem";
    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour
    private static final long REFRESH_EXPIRATION_TIME = 24000 * 60 * 60; // 24 hour


    private static PrivateKey getPrivateKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] keyBytes = Base64.getDecoder().decode(
                new String(Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE)))
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s", "")
        );
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private static PublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(
                new String(Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE)))
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s", "")
        );
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public String generateTokenfromUsername(Map<String, Object> claims, String subject, String tokenType) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey privateKey = getPrivateKey();
        long expirationTime;
        claims = new HashMap<>(claims); // Avoid modifying original map
        claims.put("token_type", tokenType + "_TOKEN");
        expirationTime = switch (tokenType.toUpperCase()) {
            case "LOGIN" -> EXPIRATION_TIME; // Assume this is defined as 900 (15 min)
            case "REFRESH" -> REFRESH_EXPIRATION_TIME; // Assume this is defined as 86400 (24 hours)
            default -> 900; // 15 minutes fallback
        };

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(expirationTime)))
                .signWith(privateKey)
                .compact();
    }

    public boolean validateJwtToken(String token) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return getClaims(token) != null;
    }

    public String getUsernameFromToken(String token) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return getClaims(token).getSubject();
    }

    public String getClaimsAsJson(String token) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Claims claims = getClaims(token);
        return new Gson().toJson(claims);
    }

    public boolean isTokenvalid(String token) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            return getClaims(token).getExpiration().after(new Date());
    }

    public boolean hasRole(String token, String role) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Claims claims = getClaims(token);
        List<String> roles = (List<String>) claims.get("roles");
        return roles != null && roles.contains(role);
    }

    public Object getClaimFromToken(String token, String claimKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return getClaims(token).get(claimKey);
    }

    public String refreshToken(String token) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Claims claims = getClaims(token);
        return generateTokenfromUsername(claims, claims.getSubject(), "REFRESH");
    }

    public Date getTokenExpiry(String token) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return getClaims(token).getExpiration();
    }

    public Map<String, Object> getAllTokenDetails(String token) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Claims claims = getClaims(token);
        Map<String, Object> tokenDetails = new HashMap<>();
        tokenDetails.put("subject", claims.getSubject());
        tokenDetails.put("issuedAt", claims.getIssuedAt());
        tokenDetails.put("expiration", claims.getExpiration());
        tokenDetails.put("claims", claims);
        return tokenDetails;
    }

    private Claims getClaims(String token) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = getPublicKey();
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public static void main(String[] args) throws Exception {

    	RSA256_JWT jwtUtility = new RSA256_JWT();

        String subject = "testUser";
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", List.of("USER", "ADMIN"));

        String token = jwtUtility.generateTokenfromUsername(claims, subject, "LOGIN");
        log.info("Generated Token: {}", token);
        log.info("Validate Token: {}", jwtUtility.validateJwtToken(token));
        log.info("Username from Token: {}", jwtUtility.getUsernameFromToken(token));
        log.info("Claims as JSON: {}", jwtUtility.getClaimsAsJson(token));
        log.info("Is Token Valid? {}", jwtUtility.isTokenvalid(token));
        log.info("Has ADMIN Role? {}", jwtUtility.hasRole(token, "ADMIN"));
        log.info("Has claims key: {}", jwtUtility.getClaimFromToken(token, "roles"));

        String refreshedToken = jwtUtility.refreshToken(token);
        log.info("Refreshed Token: {}", refreshedToken);
        log.info("Validate Refreshed Token: {}", jwtUtility.validateJwtToken(refreshedToken));
        log.info("getClaimsAsJson as JSON: {}", jwtUtility.getClaimsAsJson(refreshedToken));
        log.info("Is Refreshed Token Valid? {}", jwtUtility.isTokenvalid(refreshedToken));
        log.info("JWT Token Expiry: {}", jwtUtility.getTokenExpiry(refreshedToken));

        Map<String, Object> tokenDetails = jwtUtility.getAllTokenDetails(refreshedToken);
        log.info("getAllTokenDetails: {}", tokenDetails);
    }
}
