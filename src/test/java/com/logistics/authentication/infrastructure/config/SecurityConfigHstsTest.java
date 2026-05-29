package com.logistics.authentication.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Arranca el contexto con HSTS habilitado para ejercitar la rama
 * securityHeaders -> httpStrictTransportSecurity de SecurityConfig
 * (el test base corre con hsts-enabled=false).
 */
@SpringBootTest(properties = "app.security.hsts-enabled=true")
class SecurityConfigHstsTest {

	@Autowired
	private SecurityProperties securityProperties;

	@Test
	void contextStartsWithHstsEnabled() {
		assertThat(securityProperties.isHstsEnabled()).isTrue();
	}
}
