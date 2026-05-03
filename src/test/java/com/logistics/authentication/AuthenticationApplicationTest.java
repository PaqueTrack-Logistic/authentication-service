package com.logistics.authentication;

import org.springframework.boot.test.context.SpringBootTest;
import org.junit.jupiter.api.Test;

/**
 * Integration test that verifies the Spring Boot application context loads successfully.
 * Serves as a basic sanity check for the authentication service startup.
 */
@SpringBootTest
class AuthenticationApplicationTest {
    // Context loading is validated automatically by @SpringBootTest annotation

    @Test
    void contextLoads() {
        // Verifies the Spring context starts without errors.
    }
}
