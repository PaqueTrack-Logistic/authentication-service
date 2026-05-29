package com.logistics.authentication.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Verifica la validación de longitud mínima (32 bytes) del secreto JWT al arrancar.
 */
@ExtendWith(MockitoExtension.class)
class JwtSecretStrengthValidatorTest {

	@Mock
	private JwtProperties jwtProperties;

	@InjectMocks
	private JwtSecretStrengthValidator validator;

	@Test
	void doesNotThrowWhenSecretHasAtLeast32Bytes() {
		when(jwtProperties.getSecret()).thenReturn("0123456789012345678901234567890123"); // 34 bytes

		assertThatCode(validator::validateSecretLength).doesNotThrowAnyException();
	}

	@Test
	void throwsWhenSecretIsTooShort() {
		when(jwtProperties.getSecret()).thenReturn("too-short");

		assertThatThrownBy(validator::validateSecretLength)
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("al menos 32 bytes");
	}
}
