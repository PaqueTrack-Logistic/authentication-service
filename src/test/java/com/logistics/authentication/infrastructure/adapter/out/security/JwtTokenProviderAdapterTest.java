package com.logistics.authentication.infrastructure.adapter.out.security;

import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenProviderAdapterTest {

    private static final String SECRET = "test-secret-key-that-is-at-least-32-bytes-long!!";
    private static final long ACCESS_TTL = 3600L;
    private static final long REFRESH_TTL = 604800L;

    private JwtTokenProviderAdapter adapter;
    private SecretKey key;

    @BeforeEach
    void setUp() {
        JwtProperties props = new JwtProperties();
        props.setSecret(SECRET);
        props.setAccessTokenTtlSeconds(ACCESS_TTL);
        props.setRefreshTokenTtlSeconds(REFRESH_TTL);

        adapter = new JwtTokenProviderAdapter(props);
        key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void createAccessToken_containsExpectedClaims() {
        UUID userId = UUID.randomUUID();
        UserAccount user = UserAccount.builder()
                .id(userId)
                .email("admin@logistics.com")
                .passwordHash("hash")
                .roles(Set.of("ROLE_ADMIN"))
                .enabled(true)
                .failedLoginAttempts(0)
                .lockedUntil(null)
                .build();

        String token = adapter.createAccessToken(user);

        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertThat(claims.getSubject()).isEqualTo(userId.toString());
        assertThat(claims.get("email", String.class)).isEqualTo("admin@logistics.com");
        @SuppressWarnings("unchecked")
        List<String> roles = claims.get("roles", List.class);
        assertThat(roles).contains("ROLE_ADMIN");
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    void createAccessToken_expirationMatchesTtl() {
        UserAccount user = UserAccount.builder()
                .id(UUID.randomUUID())
                .email("user@test.com")
                .passwordHash("hash")
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .failedLoginAttempts(0)
                .lockedUntil(null)
                .build();

        String token = adapter.createAccessToken(user);

        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        long diffSeconds = (claims.getExpiration().getTime() - claims.getIssuedAt().getTime()) / 1000;
        assertThat(diffSeconds).isEqualTo(ACCESS_TTL);
    }

    @Test
    void getAccessTokenTtlSeconds_returnsConfiguredValue() {
        assertThat(adapter.getAccessTokenTtlSeconds()).isEqualTo(ACCESS_TTL);
    }

    @Test
    void getRefreshTokenTtlSeconds_returnsConfiguredValue() {
        assertThat(adapter.getRefreshTokenTtlSeconds()).isEqualTo(REFRESH_TTL);
    }
}
