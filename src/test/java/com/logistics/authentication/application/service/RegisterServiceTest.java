package com.logistics.authentication.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.application.port.in.RegisterUseCase.RegisterCommand;
import com.logistics.authentication.application.port.in.RegisterUseCase.RegisterResult;
import com.logistics.authentication.application.port.out.PasswordEncoderPort;
import com.logistics.authentication.application.port.out.RoleRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;

/**
 * Cubre el registro de usuarios: normalización del email, creación PENDING,
 * email duplicado y rol por defecto no configurado.
 */
@ExtendWith(MockitoExtension.class)
class RegisterServiceTest {

	@Mock
	private UserRepositoryPort users;

	@Mock
	private RoleRepositoryPort roles;

	@Mock
	private PasswordEncoderPort passwordEncoder;

	@InjectMocks
	private RegisterService service;

	@Test
	void register_normalizesEmailAndCreatesPendingUser() {
		UUID roleId = UUID.randomUUID();
		when(users.existsByEmail("test@logistics.com")).thenReturn(false);
		when(roles.findRoleIdByName("ROLE_OPERATOR")).thenReturn(Optional.of(roleId));
		when(passwordEncoder.encode("Secret123*")).thenReturn("hashed-pw");

		RegisterResult result = service.register(new RegisterCommand("  Test@Logistics.COM ", "Secret123*"));

		assertThat(result.status()).isEqualTo("PENDING");
		assertThat(result.email()).isEqualTo("test@logistics.com");
		assertThat(result.userId()).isNotNull();

		ArgumentCaptor<UUID> idCaptor = ArgumentCaptor.forClass(UUID.class);
		verify(users).savePendingUser(idCaptor.capture(), eq("test@logistics.com"), eq("hashed-pw"), eq(roleId));
		assertThat(idCaptor.getValue()).isEqualTo(result.userId());
	}

	@Test
	void register_throwsWhenEmailAlreadyRegistered() {
		when(users.existsByEmail("dup@e.com")).thenReturn(true);

		assertThatThrownBy(() -> service.register(new RegisterCommand("dup@e.com", "whatever1")))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_EMAIL_ALREADY_REGISTERED");

		verify(users, never()).savePendingUser(any(), any(), any(), any());
	}

	@Test
	void register_throwsWhenDefaultRoleNotConfigured() {
		when(users.existsByEmail("new@e.com")).thenReturn(false);
		when(roles.findRoleIdByName("ROLE_OPERATOR")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.register(new RegisterCommand("new@e.com", "whatever1")))
				.isInstanceOf(IllegalStateException.class);

		verify(users, never()).savePendingUser(any(), any(), any(), any());
	}
}
