package com.logistics.authentication.application.service;

import com.logistics.authentication.application.port.in.LoginUseCase.LoginResult;
import com.logistics.authentication.application.port.in.RefreshTokenUseCase.RefreshCommand;
import com.logistics.authentication.application.port.out.JwtTokenProviderPort;
import com.logistics.authentication.application.port.out.RefreshTokenIssuerPort;
import com.logistics.authentication.application.port.out.RefreshTokenRepositoryPort;
import com.logistics.authentication.application.port.out.RefreshTokenRepositoryPort.RefreshTokenActive;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.UserAccount;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private UserRepositoryPort users;

    @Mock
    private RefreshTokenRepositoryPort refreshTokens;

    @Mock
    private JwtTokenProviderPort jwtTokenProvider;

    @Mock
    private RefreshTokenIssuerPort refreshTokenIssuer;

    @Mock
    private Clock clock;

    @InjectMocks
    private RefreshTokenService service;

    private static final Instant NOW = Instant.parse("2026-01-15T10:00:00Z");
    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID TOKEN_ID = UUID.randomUUID();
    private static final String RAW_TOKEN = "raw-refresh-token";
    private static final String TOKEN_HASH = "hashed-token";
    private static final String NEW_ACCESS_TOKEN = "new-access-token";
    private static final String NEW_REFRESH_TOKEN = "new-refresh-opaque";

    private UserAccount enabledUser;

    @BeforeEach
    void setUp() {
        enabledUser = UserAccount.builder()
                .id(USER_ID)
                .email("user@test.com")
                .passwordHash("hashed")
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .failedLoginAttempts(0)
                .lockedUntil(null)
                .build();
    }

    private void stubClock() {
        when(clock.instant()).thenReturn(NOW);
    }

    @Test
    void refreshSuccessfully_returnsNewTokens() {
        stubClock();
        when(refreshTokenIssuer.sha256Hex(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(refreshTokens.findActiveByTokenHash(TOKEN_HASH, NOW))
                .thenReturn(Optional.of(new RefreshTokenActive(TOKEN_ID, USER_ID)));
        when(users.findById(USER_ID)).thenReturn(Optional.of(enabledUser));
        when(jwtTokenProvider.createAccessToken(enabledUser)).thenReturn(NEW_ACCESS_TOKEN);
        when(refreshTokenIssuer.newOpaqueToken()).thenReturn(NEW_REFRESH_TOKEN);
        when(jwtTokenProvider.getRefreshTokenTtlSeconds()).thenReturn(604800L);
        when(jwtTokenProvider.getAccessTokenTtlSeconds()).thenReturn(3600L);
        when(refreshTokenIssuer.sha256Hex(NEW_REFRESH_TOKEN)).thenReturn("new-hash");

        LoginResult result = service.refresh(new RefreshCommand(RAW_TOKEN));

        assertThat(result.accessToken()).isEqualTo(NEW_ACCESS_TOKEN);
        assertThat(result.refreshToken()).isEqualTo(NEW_REFRESH_TOKEN);
        assertThat(result.tokenType()).isEqualTo("Bearer");
        assertThat(result.expiresInSeconds()).isEqualTo(3600L);
        assertThat(result.refreshExpiresInSeconds()).isEqualTo(604800L);
        verify(refreshTokens).revokeById(TOKEN_ID);
        verify(refreshTokens).save(eq(USER_ID), eq("new-hash"), any(Instant.class));
    }

    @Test
    void refreshWithNullToken_throwsInvalidRefresh() {
        RefreshCommand command = new RefreshCommand(null);

        assertThatThrownBy(() -> service.refresh(command))
                .isInstanceOf(AuthenticationDomainException.class)
                .satisfies(ex -> {
                    AuthenticationDomainException ade = (AuthenticationDomainException) ex;
                    assertThat(ade.getErrorCode()).isEqualTo("INVALID_REFRESH");
                });
    }

    @Test
    void refreshWithBlankToken_throwsInvalidRefresh() {
        RefreshCommand command = new RefreshCommand("  ");
        assertThatThrownBy(() -> service.refresh(command))
                .isInstanceOf(AuthenticationDomainException.class)
                .satisfies(ex -> {
                    AuthenticationDomainException ade = (AuthenticationDomainException) ex;
                    assertThat(ade.getErrorCode()).isEqualTo("INVALID_REFRESH");
                });
    }

    @Test
    void refreshWithUnknownToken_throwsInvalidRefresh() {
        stubClock();
        when(refreshTokenIssuer.sha256Hex("unknown-token")).thenReturn("unknown-hash");
        when(refreshTokens.findActiveByTokenHash("unknown-hash", NOW))
                .thenReturn(Optional.empty());

        RefreshCommand command = new RefreshCommand("unknown-token");
        assertThatThrownBy(() -> service.refresh(command))
                .isInstanceOf(AuthenticationDomainException.class)
                .satisfies(ex -> {
                    AuthenticationDomainException ade = (AuthenticationDomainException) ex;
                    assertThat(ade.getErrorCode()).isEqualTo("INVALID_REFRESH");
                });
        verify(refreshTokens, never()).revokeById(any());
    }

    @Test
    void refreshWithDisabledUser_throwsAccountDisabled() {
        stubClock();
        UserAccount disabledUser = UserAccount.builder()
                .id(USER_ID)
                .email("user@test.com")
                .passwordHash("hashed")
                .roles(Set.of("ROLE_USER"))
                .enabled(false)
                .failedLoginAttempts(0)
                .lockedUntil(null)
                .build();

        when(refreshTokenIssuer.sha256Hex(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(refreshTokens.findActiveByTokenHash(TOKEN_HASH, NOW))
                .thenReturn(Optional.of(new RefreshTokenActive(TOKEN_ID, USER_ID)));
        when(users.findById(USER_ID)).thenReturn(Optional.of(disabledUser));

        RefreshCommand command = new RefreshCommand(RAW_TOKEN);

        assertThatThrownBy(() -> service.refresh(command))
                .isInstanceOf(AuthenticationDomainException.class)
                .satisfies(ex -> {
                    AuthenticationDomainException ade = (AuthenticationDomainException) ex;
                    assertThat(ade.getErrorCode()).isEqualTo("AUTH_ACCOUNT_DISABLED");
                });
        verify(refreshTokens, never()).revokeById(any());
    }

    @Test
    void refreshWithLockedUser_throwsAccountLocked() {
        stubClock();
        UserAccount lockedUser = UserAccount.builder()
                .id(USER_ID)
                .email("user@test.com")
                .passwordHash("hashed")
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .failedLoginAttempts(5)
                .lockedUntil(NOW.plusSeconds(300))
                .build();

        when(refreshTokenIssuer.sha256Hex(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(refreshTokens.findActiveByTokenHash(TOKEN_HASH, NOW))
                .thenReturn(Optional.of(new RefreshTokenActive(TOKEN_ID, USER_ID)));
        when(users.findById(USER_ID)).thenReturn(Optional.of(lockedUser));

        RefreshCommand command = new RefreshCommand(RAW_TOKEN);

        assertThatThrownBy(() -> service.refresh(command))
                .isInstanceOf(AuthenticationDomainException.class)
                .satisfies(ex -> {
                    AuthenticationDomainException ade = (AuthenticationDomainException) ex;
                    assertThat(ade.getErrorCode()).isEqualTo("AUTH_ACCOUNT_LOCKED");
                });
        verify(refreshTokens, never()).revokeById(any());
    }
}
