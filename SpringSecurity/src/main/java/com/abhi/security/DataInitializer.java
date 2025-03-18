package com.abhi.security;

import java.util.List;
import java.util.UUID;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.abhi.security.model.EndUser;
import com.abhi.security.model.Role;
import com.abhi.security.repository.UserRepository;
import com.abhi.security.utilities.AdvanceEncryptionStandard;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class DataInitializer implements CommandLineRunner {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
//	public static String SECRETE_KEY;

	public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}

	
//	public static void generateKey() throws Exception{
//		AdvanceEncryptionStandard aes = new AdvanceEncryptionStandard();
//		String strKey1 = aes.encrypt("Abhishek_Dubey");
//		String strKey2 = aes.encrypt("Abhishek_Dubey");
//		SECRETE_KEY = strKey1.concat(strKey2);
//		log.info("Key-1 :" + strKey1 + " || Key-2 :" + strKey2 + " ====> SECRETE-KEY :" + SECRETE_KEY);
//
//	}
	
	@Override
	public void run(String... args) throws Exception {
//		generateKey();
		if (userRepository.findByUsername("admin").isEmpty()) {
			EndUser admin = EndUser.builder().username("admin").useremail("admin@example.com")
					.useruniqueid(UUID.randomUUID().toString()).usercontact("8850014998")
					.password(passwordEncoder.encode("admin123")) // Encrypt password
					// Authorization : Basic base64(admin@example.com:admin123)
					.useruniqueid(UUID.randomUUID().toString()).roles(List.of(Role.USER, Role.ADMIN, Role.SUPERADMIN))
					.build();
			userRepository.save(admin);
		}

		if (userRepository.findByUsername("user").isEmpty()) {
			EndUser user = EndUser.builder().username("user").useremail("user@example.com").usercontact("9998887776")
					.password(passwordEncoder.encode("user123")) // Encrypt password
					.useruniqueid(UUID.randomUUID().toString()).roles(List.of(Role.USER)) // Single role
					.build();
			userRepository.save(user);
		}
	}
}
