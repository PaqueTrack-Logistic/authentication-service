package com.logistics.authentication.application.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
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
import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;

/**
 * Ramas no cubiertas por LoginServiceTest: mapeo de razones de auditoría para
 * PENDING y REJECTED, y bloqueo de cuenta al alcanzar el máximo de intentos.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LoginServiceBranchesTest {

	private static final UUID USER_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
	private static final String EMAIL = "admin@logistics.com";

	@Mock private UserRepositoryPort users;
	@Mock private PasswordEncoderPort passwordEncoder;
	@Mock private JwtTokenProviderPort jwtTokenProvider;
	@Mock private LoginAuditPort loginAudit;
	@Mock private RefreshTokenRepositoryPort refreshTokens;
	@Mock private RefreshTokenIssuerPort refreshTokenIssuer;
	@Mock private Clock clock;

	@InjectMocks
	private LoginService loginService;

	private final Instant now = Instant.parse("2026-04-05T12:00:00Z");

	@BeforeEach
	void setClock() {
		when(clock.instant()).thenReturn(now);
		when(clock.getZone()).thenReturn(ZoneOffset.UTC);
	}

	private UserAccount user(RegistrationStatus status, boolean enabled, int failed) {
		return UserAccount.builder()
				.id(USER_ID).email(EMAIL).passwordHash("hash")
				.roles(Set.of("ROLE_ADMIN")).enabled(enabled)
				.registrationStatus(status).failedLoginAttempts(failed).lockedUntil(null)
				.build();
	}

	@Test
	void login_pendingUser_auditsPendingApproval() {
		when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user(RegistrationStatus.PENDING, true, 0)));

		assertThatThrownBy(() -> loginService.login(new LoginCommand(EMAIL, "password123")))
				.isInstanceOf(AuthenticationDomainException.class)
				.hasFieldOrPropertyWithValue("errorCode", "AUTH_PENDING_APPROVAL");

		verify(loginAudit).recordLoginAttempt(USER_ID, EMAIL, false, "PENDING_APPROVAL");
		verify(passwordEncoder, never()).matches(any(), any());
	}

	@Test
	void login_rejectedUser_auditsRegistrationRejected() {
		when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user(RegistrationStatus.REJECTED, true, 0)));

		assertThatThrownBy(() -> loginService.login(new LoginCommand(EMAIL, "password123")))
				.isInstanceOf(AuthenticationDomainException.class)
				.hasFieldOrPropertyWithValue("errorCode", "AUTH_REGISTRATION_REJECTED");

		verify(loginAudit).recordLoginAttempt(USER_ID, EMAIL, false, "REGISTRATION_REJECTED");
	}

	@Test
	void login_badPasswordAtThreshold_locksAccount() {
		when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user(RegistrationStatus.APPROVED, true, 4)));
		when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);

		assertThatThrownBy(() -> loginService.login(new LoginCommand(EMAIL, "wrong")))
				.isInstanceOf(AuthenticationDomainException.class)
				.hasFieldOrPropertyWithValue("errorCode", "AUTH_INVALID_CREDENTIALS");

		verify(users).registerFailedLogin(USER_ID, 5, now.plus(15, ChronoUnit.MINUTES));
	}
}
