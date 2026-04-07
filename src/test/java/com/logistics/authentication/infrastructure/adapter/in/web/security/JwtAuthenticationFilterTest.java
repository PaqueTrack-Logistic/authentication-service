package com.logistics.authentication.infrastructure.adapter.in.web.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.config.JwtProperties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    private static final String SECRET = "this-is-a-very-long-secret-key-for-testing-hs256-algorithm!!";

    @Mock
    private JwtProperties jwtProperties;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter(jwtProperties, objectMapper);
        SecurityContextHolder.clearContext();
    }

    @Test
    void noAuthorizationHeader_passesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void invalidToken_passesThrough_withUnauthorizedStatus() throws Exception {
        when(jwtProperties.getSecret()).thenReturn(SECRET);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        request.addHeader("Authorization", "Bearer invalid.jwt.token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void validToken_setsSecurityContext() throws Exception {
        when(jwtProperties.getSecret()).thenReturn(SECRET);

        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .subject("user-id-123")
                .claim("email", "user@example.com")
                .claim("roles", List.of("ADMIN"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600_000))
                .signWith(key)
                .compact();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.isAuthenticated()).isTrue();

        JwtPrincipal principal = (JwtPrincipal) auth.getPrincipal();
        assertThat(principal.userId()).isEqualTo("user-id-123");
        assertThat(principal.email()).isEqualTo("user@example.com");
        assertThat(auth.getAuthorities()).anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    @Test
    void expiredToken_returns401() throws Exception {
        when(jwtProperties.getSecret()).thenReturn(SECRET);

        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .subject("user-id-123")
                .claim("email", "user@example.com")
                .claim("roles", List.of("ADMIN"))
                .issuedAt(new Date(System.currentTimeMillis() - 7200_000))
                .expiration(new Date(System.currentTimeMillis() - 3600_000))
                .signWith(key)
                .compact();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).isEqualTo("application/json");
        assertThat(response.getContentAsString()).contains("INVALID_OR_EXPIRED_TOKEN");
    }

    @Test
    void malformedToken_returns401() throws Exception {
        when(jwtProperties.getSecret()).thenReturn(SECRET);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        request.addHeader("Authorization", "Bearer not.a.valid.jwt.at.all");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("INVALID_OR_EXPIRED_TOKEN");
    }

    @Test
    void tokenWithNullRoles_setsEmptyAuthorities() throws Exception {
        when(jwtProperties.getSecret()).thenReturn(SECRET);

        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .subject("user-id-456")
                .claim("email", "noroles@example.com")
                // no roles claim at all
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600_000))
                .signWith(key)
                .compact();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getAuthorities()).isEmpty();
    }

    @Test
    void headerWithoutBearerPrefix_passesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void validToken_withRolePrefixed_doesNotDoublePrefix() throws Exception {
        when(jwtProperties.getSecret()).thenReturn(SECRET);

        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .subject("user-id-789")
                .claim("email", "prefixed@example.com")
                .claim("roles", List.of("ROLE_MANAGER"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600_000))
                .signWith(key)
                .compact();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getAuthorities()).anyMatch(a -> a.getAuthority().equals("ROLE_MANAGER"));
        assertThat(auth.getAuthorities()).noneMatch(a -> a.getAuthority().equals("ROLE_ROLE_MANAGER"));
    }

    @Test
    void shouldNotFilter_loginPath_returnsTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/auth/login");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    void shouldNotFilter_refreshPath_returnsTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/auth/refresh");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    void shouldNotFilter_protectedPath_returnsFalse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    void tokenWithSingleStringRole_extractsCorrectly() throws Exception {
        when(jwtProperties.getSecret()).thenReturn(SECRET);

        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        // Build token with roles as a single string (not a list)
        String token = Jwts.builder()
                .subject("user-single-role")
                .claim("email", "single@example.com")
                .claim("roles", "USER")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600_000))
                .signWith(key)
                .compact();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/users");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getAuthorities()).anyMatch(a -> a.getAuthority().equals("ROLE_USER"));
    }
}
