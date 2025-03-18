package com.abhi.security.config;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.abhi.security.service.CustomUserDetailsService;
import com.abhi.security.utilities.JWTEncryptionUtility;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	private JWTEncryptionUtility jwtUtil = new JWTEncryptionUtility(false);

	@Autowired
	CustomUserDetailsService userDetailService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		logger.debug("AuthTokenFilter triggered for URL: {}", request.getRequestURI());

		try {
			String bearertoken = request.getHeader("access_token");

			String jwt = jwtUtil.getJWTfromHeader(bearertoken);
			if (jwt != null) {
				logger.debug("Authorization Header JWT Token: {}", jwt);
				if (jwtUtil.validateJwtToken(jwt).equalsIgnoreCase("success")) {
					String username = jwtUtil.getUsernameFromToken(jwt);
					logger.debug("JWT contains username: {}", username);
					if (SecurityContextHolder.getContext().getAuthentication() == null) {
						UserDetails userDetails = userDetailService.loadUserByUsername(username);
						UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
								userDetails, null, userDetails.getAuthorities());
						logger.debug("Roles from JWT: {}", userDetails.getAuthorities());
						authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					}
				}
			}
		} catch (Exception e) {
			logger.error("Exception occurred in AuthTokenFilter: {}", e.getMessage(), e);
		}
		filterChain.doFilter(request, response);
	}
}