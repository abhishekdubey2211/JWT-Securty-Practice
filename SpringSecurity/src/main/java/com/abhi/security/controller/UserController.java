package com.abhi.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.abhi.security.model.EndUser;
import com.abhi.security.model.Loginequest;
import com.abhi.security.service.CustomUserDetails;
import com.abhi.security.service.CustomUserDetailsService;
import com.abhi.security.utilities.JWTUtil;

import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor

public class UserController {
	private final AuthenticationManager authenticationManager;
	private final JWTUtil jwtTokenProvider;
	private final CustomUserDetailsService userDetailsService;

	@GetMapping("/details")
	public ResponseEntity<?> getUserDetails(@RequestAttribute(name = "_csrf", required = false) CsrfToken csrfToken) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication == null || !authentication.isAuthenticated()
				|| authentication instanceof AnonymousAuthenticationToken) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(Map.of("error", "Unauthorized", "message", "User is not authenticated"));
		}

		return ResponseEntity.ok(Map.of("username", authentication.getName(), "roles",
				authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(), "data",
				authentication.getPrincipal(), "csrfToken",
				csrfToken != null ? csrfToken.getToken() : "CSRF token not available"));
	}

	@PostMapping("/login")
	public ResponseEntity<?> loginRequest(@RequestBody Loginequest request) throws Exception {
		try {
			Map<String, Object> claims = new LinkedHashMap<>();
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

			SecurityContextHolder.getContext().setAuthentication(authentication);
			CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

			claims.put("userId", userDetails.getUserid());
			claims.put("userLogin", userDetails.getUsername());
			claims.put("userUniqueId", userDetails.getUseruniqueid());
			claims.put("tokenType", "LOGIN-TOKEN");

			// Generate access token (short-lived)
			String jwtToken = jwtTokenProvider.generateToken(claims, authentication.getName());
			claims=null;
			claims = new LinkedHashMap<>();
			claims.put("userUniqueId", userDetails.getUseruniqueid());
			claims.put("refreshToken", userDetails.getRefreshtoken());
			claims.put("tokenType", "REFRESH-TOKEN");
			
			// Generate refresh token (long-lived)
	        String refreshJWTToken = jwtTokenProvider.generateToken(claims, authentication.getName(), TimeUnit.HOURS.toMillis(24));

			// Store refresh token in database/cache (implement logic)
	       EndUser user= userDetailsService.updateRefreshToken(userDetails.getUserid(), userDetails.getRefreshtoken());

	       if(user.getRefreshToken().equals( userDetails.getRefreshtoken())) {
	    	   return ResponseEntity.ok(Map.of(
	    		                "username", userDetails.getName(),
	    		                "useremail", userDetails.getUseremail(),
	    		                "useruniqueid", userDetails.getUseruniqueid(),
	    		                "jwtToken", jwtToken,
	    		                "refreshToken", refreshJWTToken,
	    		                "roles", userDetails.getAuthorities().stream()
	    		                                    .map(GrantedAuthority::getAuthority)
	    		                                    .toList()
	    		        ));
	       }else {
	    		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
						.body(Map.of("error", "Unauthorized", "message", "Fail to update RefreshToken"));
	       }
		} catch (BadCredentialsException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(Map.of("error", "Unauthorized", "message", "Invalid email or password"));
		}
	}
	

    public String generateAccessToken(CustomUserDetails userDetails,String tokenType) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("userId", userDetails.getUserid());
        claims.put("userLogin", userDetails.getUsername());
        claims.put("userUniqueId", userDetails.getUseruniqueid());
        claims.put("tokenType", tokenType+"_TOKEN");
        if(tokenType.equalsIgnoreCase("LOGIN")) {
            return jwtTokenProvider.generateToken(claims, userDetails.getUsername());
        }
        claims.put("refreshToken", userDetails.getRefreshtoken());
        return jwtTokenProvider.generateToken(claims, userDetails.getUsername(), TimeUnit.HOURS.toMillis(24));

    }


}
