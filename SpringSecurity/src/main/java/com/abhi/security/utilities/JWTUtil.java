package com.abhi.security.utilities;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.time.Instant;
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
import org.springframework.stereotype.Component;

import com.abhi.security.DataInitializer;
import com.abhi.security.SpringSecurityApplication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Component
public class JWTUtil {

	private static final Logger logger = LoggerFactory.getLogger(JWTEncryptionUtility.class);
	private String jwtSecrete =SpringSecurityApplication.SECRETE_KEY;
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final long DEFAULT_EXPIRATION = TimeUnit.MINUTES.toMillis(15);

	public String extractTokenFromHeader(String bearerToken) {
		if (bearerToken != null) {
			if (bearerToken.startsWith("Bearer ")) {
				return bearerToken.substring(7);
			}
		}
		return null;
	}

	private Key getSigningKey() {
		try {
			logger.info("jwtSecrete ::"+jwtSecrete);
			return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecrete));
		} catch (IllegalArgumentException e) {
			logger.error("Error generating signing key: {}", e.getMessage());
			throw new RuntimeException("Failed to generate signing key", e);
		}
	}

	public String generateToken(Map<String, Object> claims, String subject, long expirationTimeMillis)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		try {
			return Jwts.builder().claims(claims).subject(subject).issuedAt(new Date())
					.expiration(Date.from(Instant.now().plusMillis(expirationTimeMillis))).signWith(getSigningKey()).compact();
			
		} catch (JwtException e) {
			logger.error("Error generating JWT token: {}", e.getMessage());
			throw new RuntimeException("Failed to generate JWT token", e);
		}
	}


    public String generateToken(Map<String, Object> claims, String subject) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        return generateToken(claims, subject, DEFAULT_EXPIRATION);
    }

    public Claims parseToken(String jwtToken) {
        try {
            return Jwts.parser()
                    .verifyWith((SecretKey) getSigningKey())
                    .build()
                    .parseSignedClaims(jwtToken)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            logger.warn("Token expired: {}", e.getMessage());
            return e.getClaims();
        } catch (JwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    public String getUsernameFromToken(String jwtToken) {
        return parseToken(jwtToken).getSubject();
    }


    public Map<String, Object> getClaims(String jwtToken) {
        Map<String, Object> claimsMap = new HashMap<>();
        try {
            Claims claims = parseToken(jwtToken);
            claimsMap.putAll(claims);
        } catch (Exception e) {
            logger.error("Error getting claims from token: {}", e.getMessage());
        }
        return claimsMap;
    }

    public boolean isTokenValid(String jwtToken) {
        try {
            Claims claims = parseToken(jwtToken);
            return claims.getExpiration().after(new Date());
        } catch (Exception e) {
            logger.warn("Invalid or expired token: {}", e.getMessage());
            return false;
        }
    }
    
    public boolean isTokenExpired(String jwtToken) {
        try {
            return parseToken(jwtToken).getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }


    public String getTokenExpirationDate(String jwtToken) {
        return DATE_FORMAT.format(parseToken(jwtToken).getExpiration());
    }

    
    public String refreshToken(String jwtToken) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        Claims claims = parseToken(jwtToken);
        if (isTokenExpired(jwtToken)) {
            claims.remove("tokenType");
            claims.remove("exp");
            return generateToken(claims, claims.getSubject(), TimeUnit.MINUTES.toMillis(24));
        }
        return jwtToken;
    }
    

    public Object getClaim(String jwtToken, String claimKey) {
        try {
            return getClaims(jwtToken).get(claimKey);
        } catch (ExpiredJwtException e) {
            return e.getClaims().get(claimKey);
        } catch (Exception e) {
            return null;
        }
    }
    
    
    public void validateJwtToken(String jwtToken) {
        if (jwtToken == null || jwtToken.trim().isEmpty()) {
            throw new JwtException("Invalid Authorization key: Token is null or empty.");
        }
        try {
            Jwts.parser()
                .verifyWith((SecretKey) getSigningKey())
                .build()
                .parseSignedClaims(jwtToken);
        } catch (MalformedJwtException e) {
            throw new JwtException("Malformed Authorization key: Invalid JWT token.", e);
        } catch (ExpiredJwtException e) {
            throw new JwtException("Expired Authorization key: JWT token has expired.", e);
        } catch (UnsupportedJwtException e) {
            throw new JwtException("Unsupported Authorization key: JWT token type is unsupported.", e);
        } catch (SecurityException e) {
            throw new JwtException("Invalid Authorization key: Signature validation failed.", e);
        } catch (IllegalArgumentException e) {
            throw new JwtException("Malformed Authorization key: JWT claims string is empty.", e);
        } catch (Exception e) {
            throw new JwtException("Authorization key validation failed due to an unexpected error.", e);
        }
    }

    public Map<String, Object> getAllTokenDetails(String jwtToken) {
        if (jwtToken == null || jwtToken.trim().isEmpty()) {
            throw new RuntimeException("Invalid Authorization key: Token is null or empty.");
        }

        try {
            Jws<Claims> jws = Jwts.parser()
                .verifyWith((SecretKey) getSigningKey())
                .build()
                .parseSignedClaims(jwtToken);

            Claims claims = jws.getPayload();
            JwsHeader header = jws.getHeader();

            // Prepare a map to hold all token details
            Map<String, Object> tokenDetails = new HashMap<>();

            // Add header details
            tokenDetails.put("token", jwtToken);
            tokenDetails.put("algorithm", header.getAlgorithm());
            tokenDetails.put("type", header.getType());
            tokenDetails.put("kid", header.getKeyId());

            // Add claims (payload) details
            tokenDetails.put("subject", claims.getSubject());
            tokenDetails.put("expiration", claims.getExpiration());
            tokenDetails.put("issuedAt", claims.getIssuedAt());
            tokenDetails.put("notBefore", claims.getNotBefore());
            tokenDetails.put("id", claims.getId());
            tokenDetails.put("audience", claims.getAudience());
            tokenDetails.put("issuer", claims.getIssuer());
            tokenDetails.put("claims", claims);

            // Check token expiration status
            boolean isExpired = claims.getExpiration() != null && claims.getExpiration().before(new Date());
            tokenDetails.put("isExpired", isExpired);
            tokenDetails.put("valid", !isExpired);

            // Extract signature
            String[] tokenParts = jwtToken.split("\\.");
            if (tokenParts.length == 3) {
                tokenDetails.put("signature", tokenParts[2]);
            }

            return tokenDetails;
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Expired Authorization key: JWT token has expired.", e);
        } catch (MalformedJwtException e) {
            throw new RuntimeException("Malformed Authorization key: Invalid JWT token.", e);
        } catch (UnsupportedJwtException e) {
            throw new RuntimeException("Unsupported Authorization key: JWT token type is unsupported.", e);
        } catch (SecurityException e) {
            throw new RuntimeException("Invalid Authorization key: Signature validation failed.", e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Malformed Authorization key: JWT claims string is empty.", e);
        } catch (Exception e) {
            throw new RuntimeException("Authorization key validation failed due to an unexpected error.", e);
        }
    }
//
//        public static void main(String[] args) throws Exception {
//            // Initialize the secret key (assuming DataInitializer provides it)
////            DataInitializer.generateKey();
//
//            // Create an instance of JWTUtil
//            JWTUtil jwtUtil = new JWTUtil();
//
//            // Sample user details and claims
//            String subject = "testUser";
//            Map<String, Object> claims = new HashMap<>();
//            claims.put("roles", List.of("USER", "ADMIN"));
//
//            // Generate a token
//            String token = jwtUtil.generateToken(claims, subject);
//            
//            
////            String token ="eyJhbGciOiJIUzUxMiJ9.eyJyb2xlcyI6WyJVU0VSIiwiQURNSU4iXSwic3ViIjoidGVzdFVzZXIiLCJpYXQiOjE3NDIxMjg2OTcsImV4cCI6MTc0MjEzNTg5N30.g3HhucxI77imn9zsgbuRfk7Gw7GYnYTT97BmdCmXAEJ7Kewwa6C46cBGHn22YWf5NYIWKllpRSvlCQYRVW9nog";
//            System.out.println("Generated Token: " + token);
//
//            // Validate the generated token
//            System.out.println("Validate Token: " + jwtUtil.isTokenValid(token));
//
//            // Get username from the token
//            System.out.println("Username from Token: " + jwtUtil.getUsernameFromToken(token));
//
//            // Get claims
//            System.out.println("Claims: " + jwtUtil.getClaims(token));
//
//            // Check if the token is expired
//            System.out.println("Is Token Expired? " + jwtUtil.isTokenExpired(token));
//
//            // Get specific claim (e.g., roles)
//            System.out.println("Roles from Token: " + jwtUtil.getClaim(token, "roles"));
//
//            // Refresh the token
//            String refreshedToken = jwtUtil.refreshToken(token);
//            System.out.println("Refreshed Token: " + refreshedToken);
//
//            // Validate the refreshed token
//            System.out.println("Validate Refreshed Token: " + jwtUtil.isTokenValid(refreshedToken));
//
//            // Get token expiration date
//            System.out.println("JWT Token Expiry: " + jwtUtil.getTokenExpirationDate(refreshedToken));
//
//            // Get all token details
//            Map<String, Object> tokenDetails = jwtUtil.getAllTokenDetails(refreshedToken);
//            System.out.println("Token Details: " + tokenDetails);
//        }
}