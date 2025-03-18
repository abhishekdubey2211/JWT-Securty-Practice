package com.abhi.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.abhi.security.utilities.AdvanceEncryptionStandard;

import jakarta.annotation.PostConstruct;

@SpringBootApplication
public class SpringSecurityApplication {

    private static final Logger logger = LoggerFactory.getLogger(SpringSecurityApplication.class);
    public static String SECRETE_KEY;

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

    @PostConstruct
    public void init() {
        generateKey(); // Ensure SECRETE_KEY is initialized before Spring context starts
        logger.info("Application started successfully. SECRETE_KEY initialized.");
    }

    public static void generateKey() {
        try {
            AdvanceEncryptionStandard aes = new AdvanceEncryptionStandard();
            String strKey1 = aes.encrypt("Abhishek_Dubey");
            String strKey2 = aes.encrypt("Abhishek_Dubey");
            SECRETE_KEY = strKey1.concat(strKey2);
            logger.info("Key-1: {} || Key-2: {} ====> SECRETE-KEY: {}", strKey1, strKey2, SECRETE_KEY);
        } catch (Exception e) {
            logger.error("Error generating secret key", e);
            throw new RuntimeException("Failed to generate secret key", e);
        }
    }
}
