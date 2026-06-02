package com.logistics.authentication.application.service;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.logistics.authentication.application.port.in.LoginUseCase;
import com.logistics.authentication.application.port.out.JwtTokenProviderPort;
import com.logistics.authentication.application.port.out.LoginAuditPort;
import com.logistics.authentication.application.port.out.PasswordEncoderPort;
import com.logistics.authentication.application.port.out.RefreshTokenIssuerPort;
import com.logistics.authentication.application.port.out.RefreshTokenRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.domain.service.LoginAuditReasonMapper;
import com.logistics.authentication.domain.service.UserAuthenticationPolicy;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class LoginService implements LoginUseCase {

	private static final int MAX_FAILED_ATTEMPTS = 5;
	private static final int LOCK_MINUTES = 15;

	private final UserRepositoryPort users;
	private final PasswordEncoderPort passwordEncoder;
	private final JwtTokenProviderPort jwtTokenProvider;
	private final LoginAuditPort loginAudit;
	private final RefreshTokenRepositoryPort refreshTokens;
	private final RefreshTokenIssuerPort refreshTokenIssuer;
	private final Clock clock;

	@Override
	@Transactional
	public LoginResult login(LoginCommand command) {
		Instant now = clock.instant();
		String normalizedEmail = command.email().trim().toLowerCase();
		UserAccount user = resolveUserOrFail(normalizedEmail, command.email());
		assertCanAuthenticate(user);
		assertPasswordMatches(user, command.rawPassword(), now);
		return issueLoginResult(user, now);
	}

	private UserAccount resolveUserOrFail(String normalizedEmail, String auditEmail) {
		return users.findByEmail(normalizedEmail)
				.orElseThrow(() -> {
					loginAudit.recordLoginAttempt(null, auditEmail, false, "USER_NOT_FOUND");
					return new AuthenticationDomainException("AUTH_INVALID_CREDENTIALS", "Credenciales inválidas");
				});
	}

	private void assertCanAuthenticate(UserAccount user) {
		try {
			UserAuthenticationPolicy.assertCanAuthenticate(user, clock.instant());
		} catch (AuthenticationDomainException ex) {
			loginAudit.recordLoginAttempt(
					user.getId(),
					user.getEmail(),
					false,
					LoginAuditReasonMapper.forAuthError(ex.getErrorCode()));
			throw ex;
		}
	}

	private void assertPasswordMatches(UserAccount user, String rawPassword, Instant now) {
		if (passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
			return;
		}
		registerFailedPasswordAttempt(user, now);
		loginAudit.recordLoginAttempt(user.getId(), user.getEmail(), false, "BAD_PASSWORD");
		throw new AuthenticationDomainException("AUTH_INVALID_CREDENTIALS", "Credenciales inválidas");
	}

	private void registerFailedPasswordAttempt(UserAccount user, Instant now) {
		int next = user.getFailedLoginAttempts() + 1;
		Instant lockUntil = next >= MAX_FAILED_ATTEMPTS
				? now.plus(LOCK_MINUTES, ChronoUnit.MINUTES)
				: null;
		users.registerFailedLogin(user.getId(), next, lockUntil);
	}

	private LoginResult issueLoginResult(UserAccount user, Instant now) {
		users.resetFailedLogin(user.getId());
		String token = jwtTokenProvider.createAccessToken(user);
		loginAudit.recordLoginAttempt(user.getId(), user.getEmail(), true, null);

		refreshTokens.revokeAllForUser(user.getId());
		String refreshPlain = refreshTokenIssuer.newOpaqueToken();
		Instant refreshExp = now.plusSeconds(jwtTokenProvider.getRefreshTokenTtlSeconds());
		refreshTokens.save(user.getId(), refreshTokenIssuer.sha256Hex(refreshPlain), refreshExp);

		return new LoginResult(
				token,
				"Bearer",
				jwtTokenProvider.getAccessTokenTtlSeconds(),
				user.getRoles(),
				refreshPlain,
				jwtTokenProvider.getRefreshTokenTtlSeconds());
	}
}
