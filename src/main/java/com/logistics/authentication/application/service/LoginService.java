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
		var userOpt = users.findByEmail(command.email().trim().toLowerCase());

		if (userOpt.isEmpty()) {
			loginAudit.recordLoginAttempt(null, command.email(), false, "USER_NOT_FOUND");
			throw new AuthenticationDomainException("AUTH_INVALID_CREDENTIALS", "Credenciales inválidas");
		}

		UserAccount user = userOpt.get();

		try {
			UserAuthenticationPolicy.assertCanAuthenticate(user, now);
		} catch (AuthenticationDomainException ex) {
			String reason = switch (ex.getErrorCode()) {
				case "AUTH_PENDING_APPROVAL" -> "PENDING_APPROVAL";
				case "AUTH_REGISTRATION_REJECTED" -> "REGISTRATION_REJECTED";
				case "AUTH_ACCOUNT_DISABLED" -> "USER_DISABLED";
				case "AUTH_ACCOUNT_LOCKED" -> "ACCOUNT_LOCKED";
				default -> "AUTH_BLOCKED";
			};
			loginAudit.recordLoginAttempt(user.getId(), user.getEmail(), false, reason);
			throw ex;
		}

		boolean passwordOk = passwordEncoder.matches(command.rawPassword(), user.getPasswordHash());
		if (!passwordOk) {
			int next = user.getFailedLoginAttempts() + 1;
			Instant lockUntil = null;
			if (next >= MAX_FAILED_ATTEMPTS) {
				lockUntil = now.plus(LOCK_MINUTES, ChronoUnit.MINUTES);
			}
			users.registerFailedLogin(user.getId(), next, lockUntil);
			loginAudit.recordLoginAttempt(user.getId(), user.getEmail(), false, "BAD_PASSWORD");
			throw new AuthenticationDomainException("AUTH_INVALID_CREDENTIALS", "Credenciales inválidas");
		}

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
