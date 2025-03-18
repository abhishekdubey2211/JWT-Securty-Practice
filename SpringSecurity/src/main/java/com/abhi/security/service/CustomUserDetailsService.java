package com.abhi.security.service;

import com.abhi.security.model.EndUser;
import com.abhi.security.repository.UserRepository;
import com.abhi.security.utilities.EncryptionUtil;

import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String useremail) throws UsernameNotFoundException {
		EndUser user = userRepository.findByUseremail(useremail)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + useremail));
		String refreshToken = UUID.randomUUID().toString();
		return CustomUserDetails.builder().userid(user.getUserid()).name(user.getUsername())
				.useremail(user.getUseremail()).useruniqueid(user.getUseruniqueid()).password(user.getPassword())
				.authorities(user.getRoles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
						.collect(Collectors.toList()))
				.refreshtoken(refreshToken + "/" + System.currentTimeMillis() + "/" + user.getUseruniqueid())
				.build();
	}

	public EndUser updateRefreshToken(Long userId, String refreshToken) {
		EndUser user = userRepository.findById(userId)
				.orElseThrow(() -> new RuntimeException("User with UserId " + userId + " does not exists"));
		user.setRefreshToken(refreshToken);
		return userRepository.save(user);
	}
}
