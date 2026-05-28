package com.logistics.authentication.application.service;

import java.time.Clock;
import java.time.Instant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.logistics.authentication.application.port.in.LoginUseCase.LoginResult;
import com.logistics.authentication.application.port.in.RefreshTokenUseCase;
import com.logistics.authentication.application.port.out.JwtTokenProviderPort;
import com.logistics.authentication.application.port.out.RefreshTokenIssuerPort;
import com.logistics.authentication.application.port.out.RefreshTokenRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.domain.service.UserAuthenticationPolicy;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService implements RefreshTokenUseCase {

	private final UserRepositoryPort users;
	private final RefreshTokenRepositoryPort refreshTokens;
	private final JwtTokenProviderPort jwtTokenProvider;
	private final RefreshTokenIssuerPort refreshTokenIssuer;
	private final Clock clock;

	@Override
	@Transactional
	public LoginResult refresh(RefreshCommand command) {
		if (command.rawRefreshToken() == null || command.rawRefreshToken().isBlank()) {
			throw new AuthenticationDomainException("INVALID_REFRESH", "Refresh token requerido");
		}
		Instant now = clock.instant();
		String hash = refreshTokenIssuer.sha256Hex(command.rawRefreshToken().trim());
		var active = refreshTokens.findActiveByTokenHash(hash, now)
				.orElseThrow(() -> new AuthenticationDomainException("INVALID_REFRESH", "Refresh token inválido o revocado"));

		UserAccount user = users.findById(active.userId())
				.orElseThrow(() -> new AuthenticationDomainException("INVALID_REFRESH", "Usuario no encontrado"));

		UserAuthenticationPolicy.assertCanAuthenticate(user, now);

		refreshTokens.revokeById(active.id());

		String access = jwtTokenProvider.createAccessToken(user);
		String newRefreshPlain = refreshTokenIssuer.newOpaqueToken();
		Instant refreshExp = now.plusSeconds(jwtTokenProvider.getRefreshTokenTtlSeconds());
		refreshTokens.save(user.getId(), refreshTokenIssuer.sha256Hex(newRefreshPlain), refreshExp);

		return new LoginResult(
				access,
				"Bearer",
				jwtTokenProvider.getAccessTokenTtlSeconds(),
				user.getRoles(),
				newRefreshPlain,
				jwtTokenProvider.getRefreshTokenTtlSeconds());
	}
}
