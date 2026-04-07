package com.logistics.authentication.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import com.logistics.authentication.application.port.in.LoginUseCase.LoginCommand;
import com.logistics.authentication.application.port.out.JwtTokenProviderPort;
import com.logistics.authentication.application.port.out.LoginAuditPort;
import com.logistics.authentication.application.port.out.PasswordEncoderPort;
import com.logistics.authentication.application.port.out.RefreshTokenIssuerPort;
import com.logistics.authentication.application.port.out.RefreshTokenRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.UserAccount;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LoginServiceTest {

	private static final UUID USER_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");

	@Mock
	private UserRepositoryPort users;
	@Mock
	private PasswordEncoderPort passwordEncoder;
	@Mock
	private JwtTokenProviderPort jwtTokenProvider;
	@Mock
	private LoginAuditPort loginAudit;
	@Mock
	private RefreshTokenRepositoryPort refreshTokens;
	@Mock
	private RefreshTokenIssuerPort refreshTokenIssuer;
	@Mock
	private Clock clock;

	@InjectMocks
	private LoginService loginService;

	private final Instant now = Instant.parse("2026-04-05T12:00:00Z");

	@BeforeEach
	void setClock() {
		when(clock.instant()).thenReturn(now);
		when(clock.getZone()).thenReturn(ZoneOffset.UTC);
	}

	@Test
	void login_success_returnsToken() {
		var user = baseUser(0, null);
		when(users.findByEmail("admin@logistics.com")).thenReturn(Optional.of(user));
		when(passwordEncoder.matches("password123", user.getPasswordHash())).thenReturn(true);
		when(jwtTokenProvider.createAccessToken(user)).thenReturn("jwt-token");
		when(jwtTokenProvider.getAccessTokenTtlSeconds()).thenReturn(3600L);
		when(jwtTokenProvider.getRefreshTokenTtlSeconds()).thenReturn(604800L);
		when(refreshTokenIssuer.newOpaqueToken()).thenReturn("opaque-refresh");
		when(refreshTokenIssuer.sha256Hex("opaque-refresh")).thenReturn("hash-refresh");

		var result = loginService.login(new LoginCommand("admin@logistics.com", "password123"));

		assertThat(result.accessToken()).isEqualTo("jwt-token");
		assertThat(result.refreshToken()).isEqualTo("opaque-refresh");
		assertThat(result.refreshExpiresInSeconds()).isEqualTo(604800L);
		assertThat(result.roles()).containsExactlyInAnyOrder("ROLE_ADMIN");
		verify(users).resetFailedLogin(USER_ID);
		verify(loginAudit).recordLoginAttempt(USER_ID, "admin@logistics.com", true, null);
		verify(refreshTokens).revokeAllForUser(USER_ID);
		verify(refreshTokens).save(eq(USER_ID), eq("hash-refresh"), any(Instant.class));
	}

	@Test
	void login_unknownUser_throws401() {
		when(users.findByEmail("x@y.com")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> loginService.login(new LoginCommand("x@y.com", "password123")))
				.isInstanceOf(AuthenticationDomainException.class)
				.hasFieldOrPropertyWithValue("errorCode", "AUTH_INVALID_CREDENTIALS");

		verify(loginAudit).recordLoginAttempt(null, "x@y.com", false, "USER_NOT_FOUND");
		verify(passwordEncoder, never()).matches(any(), any());
	}

	@Test
	void login_badPassword_incrementsAttempts() {
		var user = baseUser(0, null);
		when(users.findByEmail("admin@logistics.com")).thenReturn(Optional.of(user));
		when(passwordEncoder.matches("wrong", user.getPasswordHash())).thenReturn(false);

		assertThatThrownBy(() -> loginService.login(new LoginCommand("admin@logistics.com", "wrong")))
				.isInstanceOf(AuthenticationDomainException.class);

		verify(users).registerFailedLogin(USER_ID, 1, null);
		verify(loginAudit).recordLoginAttempt(USER_ID, "admin@logistics.com", false, "BAD_PASSWORD");
	}

	@Test
	void login_lockedAccount_throws403() {
		var user = baseUser(0, now.plusSeconds(60));
		when(users.findByEmail("admin@logistics.com")).thenReturn(Optional.of(user));

		assertThatThrownBy(() -> loginService.login(new LoginCommand("admin@logistics.com", "password123")))
				.isInstanceOf(AuthenticationDomainException.class)
				.hasFieldOrPropertyWithValue("errorCode", "AUTH_ACCOUNT_LOCKED");

		verify(passwordEncoder, never()).matches(any(), any());
	}

	@Test
	void login_disabledUser_throws403() {
		var user = UserAccount.builder()
				.id(USER_ID)
				.email("admin@logistics.com")
				.passwordHash("hash")
				.roles(Set.of("ROLE_ADMIN"))
				.enabled(false)
				.failedLoginAttempts(0)
				.lockedUntil(null)
				.build();
		when(users.findByEmail("admin@logistics.com")).thenReturn(Optional.of(user));

		assertThatThrownBy(() -> loginService.login(new LoginCommand("admin@logistics.com", "password123")))
				.isInstanceOf(AuthenticationDomainException.class)
				.hasFieldOrPropertyWithValue("errorCode", "AUTH_ACCOUNT_DISABLED");
	}

	private static UserAccount baseUser(int failed, Instant lockedUntil) {
		return UserAccount.builder()
				.id(USER_ID)
				.email("admin@logistics.com")
				.passwordHash("hash")
				.roles(Set.of("ROLE_ADMIN"))
				.enabled(true)
				.failedLoginAttempts(failed)
				.lockedUntil(lockedUntil)
				.build();
	}
}
