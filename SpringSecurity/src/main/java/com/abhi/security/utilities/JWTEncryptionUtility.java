package com.abhi.security.utilities;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.abhi.security.DataInitializer;
import com.abhi.security.SpringSecurityApplication;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTEncryptionUtility {

	private static final Logger logger = LoggerFactory.getLogger(JWTEncryptionUtility.class);
	private String jwtSecrete = SpringSecurityApplication.SECRETE_KEY;
	private static final SimpleDateFormat sf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	private final boolean isEncryptedJWT;
	private final SecurityHandler securityHandler;

	 public JWTEncryptionUtility(@Value("${jwt.encrypted}") boolean isEncryptedJWT) {
	        this.isEncryptedJWT = isEncryptedJWT;
	        this.securityHandler = new SecurityHandler();
	    }

	public String getJWTfromHeader(String bearerToken) {
		if (bearerToken != null) {
			if (isEncryptedJWT) {
				return bearerToken;
			}
			if (bearerToken.startsWith("Bearer ")) {
				return bearerToken.substring(7); 
			}
		}
		return null;
	}

	public String encryptedJWT(String jwtToken)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		return securityHandler.AESencrypt(jwtToken);
	}

	public String decryptedJWT(String encryptedJWT)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		return securityHandler.AESdecrypt(encryptedJWT);
	}

	
	
	private Key key() {
		try {
			return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecrete));
		} catch (IllegalArgumentException e) {
			logger.error("Error generating key: {}", e.getMessage());
			throw e;
		}
	}

	
	
	public String generateTokenWithCustomExpiration(Map<String, Object> claims, String subject,
			long expirationTimeMillis)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			String jwtToken = Jwts.builder().claims(claims).subject(subject).issuedAt(new Date())
					.expiration(Date.from(Instant.now().plusMillis(expirationTimeMillis))).signWith(key()).compact();
			return (isEncryptedJWT) ? encryptedJWT(jwtToken) : jwtToken;
		} catch (Exception e) {
			logger.error("Error generating token with custom expiration: {}", e.getMessage());
			return null;
		}
	}

	public String generateTokenfromUsername(Map<String, Object> claims, String subject)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			String jwtToken = Jwts.builder().claims(claims).subject(subject).issuedAt(new Date())
					.expiration(Date.from(Instant.now().plusMillis(TimeUnit.SECONDS.toMillis(120)))).signWith(key())
					.compact();
			return (isEncryptedJWT) ? encryptedJWT(jwtToken) : jwtToken;
		} catch (Exception e) {
			logger.error("Error generating token from username: {}", e.getMessage());
			return null;
		}
	}

	public String getUsernameFromToken(String jwtToken)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;

			return Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken).getPayload()
					.getSubject();
		} catch (Exception e) {
			logger.error("Error getting username from token: {}", e.getMessage());
			return null;
		}
	}

	public Claims getClaims(String jwtToken)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;
			return Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken).getPayload();
		} catch (Exception e) {
			logger.error("Error getting claims from token: {}", e.getMessage());
			return null;
		}
	}

	public String getClaimsAsJson(String jwtToken) {
		Gson gson = new Gson();
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;
			Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken)
					.getPayload();
			return gson.toJson(claims);
		} catch (JsonSyntaxException e) {
			logger.error("Error converting claims to JSON: {}", e.getMessage());
		} catch (Exception e) {
			logger.error("Error getting claims from token: {}", e.getMessage());
		}
		return jwtToken;
	}

	public boolean isTokenvalid(String jwtToken) throws Exception {
		jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;
		Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken).getPayload();
		return claims.getExpiration().after(Date.from(Instant.now()));
	}

	// 1. Extract a specific claim from the token
	public Object getClaimFromToken(String jwtToken, String claimKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;
			Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken)
					.getPayload();
			return claims.get(claimKey);
		} catch (ExpiredJwtException e) {
			 Claims claims = e.getClaims(); // Extract claims even when expired
		        logger.warn("JWT expired, but extracting claim {} from token: {}", claimKey, e.getMessage());
		        return claims.get(claimKey);
		}catch(Exception e) {
			return null;
		}
	}

	public boolean isTokenExpired(String jwtToken)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;
			Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken)
					.getPayload();
			return claims.getExpiration().before(new Date());
		} catch (Exception e) {
			logger.error("Error checking token expiration: {}", e.getMessage());
			return true; // Consider it expired if there's an error
		}
	}

	public String getTokenExpiry(String jwtToken)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;
		Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken).getPayload();
		return  sf.format(claims.getExpiration());
	}

	public String refreshToken(String jwtToken)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;

			if (Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken).getPayload()
					.getExpiration().before(new Date())) {
				Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken)
						.getPayload();
				if (claims == null) {
					logger.error("Claims are null, cannot refresh token.");
					return null;
				}
				Map<String, Object> newClaims = new HashMap<>(claims);
				newClaims.put("tokentype", "REFRESH_TOKEN");
				return generateTokenfromUsername(newClaims, claims.getSubject().toString());
			}
			return (isEncryptedJWT) ? encryptedJWT(jwtToken) : jwtToken;
		} catch (Exception e) {
			logger.error("Error refreshing token: {}", e.getMessage());
			return null;
		}
	}

	// 4. Check if the user has a specific role
	public boolean hasRole(String jwtToken, String roleName)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;
			Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken)
					.getPayload();
			List<String> roles = (List<String>) claims.get("roles");
			return roles.contains(roleName);
		} catch (Exception e) {
			logger.error("Error checking role {} in token: {}", roleName, e.getMessage());
			return false;
		}
	}

	public List<String> getRolesFromToken(String jwtToken)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;

			Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken)
					.getPayload();

			return (List<String>) claims.get("roles");
		} catch (Exception e) {
			logger.error("Error getting roles from token: {}", e.getMessage());
			return Collections.emptyList();
		}
	}

	public String validateJwtToken(String jwtToken) {
		try {
			jwtToken = (isEncryptedJWT) ? decryptedJWT(jwtToken) : jwtToken;
			Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken);
			return "success";
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT Token: {}" ,e.getMessage());
			return "Malformed  Authorization key ";
		} catch (ExpiredJwtException e) {
			logger.error("JWT token expired: {}", e.getMessage());
			return "Expired Authorization key";
		} catch (UnsupportedJwtException e) {
			logger.error("Unsupported JWT Token: {}", e.getMessage());
			return "Unsupported Authorization key";
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty: {}", e.getMessage());
			return "Malformed Authorization key";
		} catch (Exception e) {
			logger.error("An unexpected error occurred during JWT validation: {}", e.getMessage());
			return "Authorization Key not found.";
		}
	}

	public String getDecryptedJWT(String encryptedJWT) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		return decryptedJWT(encryptedJWT) ;
	}
	
	public Map<String, Object> getAllTokenDetails(String token)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		Gson gson = new Gson();
		try {
			String jwtToken = (isEncryptedJWT) ? decryptedJWT(token) : token;

			Jws<Claims> jws = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken);

			Claims claims = Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken)
					.getPayload();

			JwsHeader header = jws.getHeader();

			// Prepare a map to hold all token details
			Map<String, Object> tokenDetails = new HashMap<>();

			// Add header details
			tokenDetails.put("token", jwtToken); // Signature algorithm
			tokenDetails.put("algorithm", header.getAlgorithm()); // Signature algorithm
			tokenDetails.put("type", header.getType()); // Token type (JWT)
			tokenDetails.put("kid", header.getKeyId()); // Key ID, if present

			// Add claims (payload) details
			tokenDetails.put("subject", claims.getSubject());
			tokenDetails.put("expiration", claims.getExpiration());
			tokenDetails.put("issuedAt", claims.getIssuedAt());
			tokenDetails.put("notBefore", claims.getNotBefore());
			tokenDetails.put("id", claims.getId()); // JWT ID, if present
			tokenDetails.put("audience", claims.getAudience()); // Audience, if present
			tokenDetails.put("issuer", claims.getIssuer()); // Issuer, if present
			tokenDetails.put("claims", claims); // All claims

			boolean isExpired = claims.getExpiration().before(new Date());
			tokenDetails.put("isExpired", isExpired); // Check if the token is expired
			tokenDetails.put("valid", !isExpired); // Validity status of the token

			// Split the JWT to get the signature part
			String[] tokenParts = jwtToken.split("\\.");
			if (tokenParts.length == 3) {
				tokenDetails.put("signature", tokenParts[2]);
			}
			return tokenDetails; // Convert the map to JSON
		} catch (Exception e) {
			logger.error("Error getting all token details: {}", e.getMessage());
	        return new HashMap<>();
		}
	}

	// Main method for testing
	public static void main(String[] args) throws Exception {
//		DataInitializer.generateKey();
		
		JWTEncryptionUtility jwtUtility = new JWTEncryptionUtility(false);

		// Sample user details and claims
		String subject = "testUser";

		Map<String, Object> claims = new HashMap<>();
		claims.put("roles", List.of("USER", "ADMIN"));

		// Generate a token
		String token = jwtUtility.generateTokenfromUsername(claims, subject);

		System.out.println("Generated Token: " + token);

		// Validate the generated token
		System.out.println("Validate Token: " + jwtUtility.validateJwtToken(token));

		// Get username from the token
		System.out.println("Username from Token: " + jwtUtility.getUsernameFromToken(token));

		// Get claims as JSON
		System.out.println("Claims as JSON: " + jwtUtility.getClaimsAsJson(token));

		// Check if the token is valid
		System.out.println("Is Token Valid? " + jwtUtility.isTokenvalid(token));

		// Check if the user has a specific role
		System.out.println("Has ADMIN Role? " + jwtUtility.hasRole(token, "ADMIN"));

		System.out.println("Has claims key " + jwtUtility.getClaimFromToken(token, "roles"));

		// Refresh the token
		String refreshedToken = jwtUtility.refreshToken(token);

		System.out.println("Refreshed Token: " + refreshedToken);

		// Validate the refreshed token
		System.out.println("Validate Refreshed Token: " + jwtUtility.validateJwtToken(refreshedToken));

		// Get claims as JSON
		System.out.println("getClaimsAsJson as JSON: " + jwtUtility.getClaimsAsJson(token));

		// Check if the refreshed token is valid
		System.out.println("Is Refreshed Token Valid? " + jwtUtility.isTokenvalid(refreshedToken));
		System.out.println("JWT Tojen Expiry  " + jwtUtility.getTokenExpiry(refreshedToken));

		Map<String, Object> tokenDetails = jwtUtility.getAllTokenDetails(refreshedToken);
		System.out.println("getAllTokenDetails : " + tokenDetails);

	}
}