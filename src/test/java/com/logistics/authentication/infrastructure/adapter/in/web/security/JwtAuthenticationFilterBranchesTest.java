package com.logistics.authentication.infrastructure.adapter.in.web.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.adapter.in.web.filter.TraceIdFilter;
import com.logistics.authentication.infrastructure.config.JwtProperties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Cubre las ramas que el test base no alcanza: rutas de documentación en
 * shouldNotFilter, roles nulos/en blanco, y propagación del traceId
 * (cabecera y MDC) al construir el 401.
 */
@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterBranchesTest {

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

	@AfterEach
	void tearDown() {
		SecurityContextHolder.clearContext();
		MDC.clear();
	}

	private MockHttpServletRequest req(String path, String authorization) {
		MockHttpServletRequest r = new MockHttpServletRequest();
		r.setServletPath(path);
		if (authorization != null) {
			r.addHeader("Authorization", authorization);
		}
		return r;
	}

	private String signedTokenWithRoles(List<String> roles) {
		SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
		return Jwts.builder()
				.subject("user-id")
				.claim("email", "user@example.com")
				.claim("roles", roles)
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + 3_600_000))
				.signWith(key)
				.compact();
	}

	@Test
	void shouldNotFilter_apiDocsPath() {
		assertThat(filter.shouldNotFilter(req("/v3/api-docs/swagger-config", null))).isTrue();
	}

	@Test
	void shouldNotFilter_swaggerUiResources() {
		assertThat(filter.shouldNotFilter(req("/swagger-ui/index.html", null))).isTrue();
	}

	@Test
	void shouldNotFilter_swaggerUiHtml() {
		assertThat(filter.shouldNotFilter(req("/swagger-ui.html", null))).isTrue();
	}

	@Test
	void rolesWithNullAndBlank_areIgnored() throws Exception {
		when(jwtProperties.getSecret()).thenReturn(SECRET);
		String token = signedTokenWithRoles(Arrays.asList("ADMIN", null, "   ", ""));
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilterInternal(req("/api/v1/users", "Bearer " + token), response, new MockFilterChain());

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		assertThat(auth).isNotNull();
		assertThat(auth.getAuthorities()).extracting("authority").containsExactly("ROLE_ADMIN");
	}

	@Test
	void invalidToken_withTraceIdHeader_returns401WithTrace() throws Exception {
		when(jwtProperties.getSecret()).thenReturn(SECRET);
		MockHttpServletRequest request = req("/api/v1/users", "Bearer not-a-valid-token");
		request.addHeader(TraceIdFilter.TRACE_ID_HEADER, "trace-from-header");
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilterInternal(request, response, new MockFilterChain());

		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getContentAsString()).contains("trace-from-header");
	}

	@Test
	void invalidToken_withTraceIdInMdc_returns401WithTrace() throws Exception {
		when(jwtProperties.getSecret()).thenReturn(SECRET);
		MDC.put(TraceIdFilter.TRACE_ID_MDC, "trace-from-mdc");
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilterInternal(req("/api/v1/users", "Bearer not-a-valid-token"), response, new MockFilterChain());

		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getContentAsString()).contains("trace-from-mdc");
	}
}
