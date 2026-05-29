package com.logistics.authentication.infrastructure.adapter.in.web.filter;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.config.SecurityProperties;

/**
 * Ramas no cubiertas del rate limiter: endpoint /refresh, resolución de IP por
 * X-Forwarded-For y traceId en la respuesta 429.
 */
class LoginRateLimitFilterBranchesTest {

	private LoginRateLimitFilter filter;

	@BeforeEach
	void setUp() {
		SecurityProperties props = new SecurityProperties();
		props.setLoginRateLimitPerMinute(3);
		filter = new LoginRateLimitFilter(props, new ObjectMapper());
	}

	private MockHttpServletResponse fire(String path, String remoteAddr, String xff, String traceId) throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
		request.setServletPath(path);
		if (remoteAddr != null) {
			request.setRemoteAddr(remoteAddr);
		}
		if (xff != null) {
			request.addHeader("X-Forwarded-For", xff);
		}
		if (traceId != null) {
			request.addHeader(TraceIdFilter.TRACE_ID_HEADER, traceId);
		}
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilterInternal(request, response, new MockFilterChain());
		return response;
	}

	@Test
	void refreshEndpointIsAlsoRateLimited() throws Exception {
		for (int i = 0; i < 3; i++) {
			fire("/api/v1/auth/refresh", "10.1.1.1", null, null);
		}
		MockHttpServletResponse blocked = fire("/api/v1/auth/refresh", "10.1.1.1", null, null);
		assertThat(blocked.getStatus()).isEqualTo(429);
	}

	@Test
	void usesXForwardedForToIdentifyClient() throws Exception {
		String xff = "203.0.113.5, 10.0.0.9";
		for (int i = 0; i < 3; i++) {
			fire("/api/v1/auth/login", "127.0.0.1", xff, null);
		}
		MockHttpServletResponse blocked = fire("/api/v1/auth/login", "127.0.0.1", xff, null);
		assertThat(blocked.getStatus()).isEqualTo(429);
	}

	@Test
	void rateLimitResponseIncludesTraceIdFromHeader() throws Exception {
		String ip = "10.2.2.2";
		for (int i = 0; i < 3; i++) {
			fire("/api/v1/auth/login", ip, null, "trace-429");
		}
		MockHttpServletResponse blocked = fire("/api/v1/auth/login", ip, null, "trace-429");
		assertThat(blocked.getStatus()).isEqualTo(429);
		assertThat(blocked.getContentAsString()).contains("RATE_LIMIT_EXCEEDED").contains("trace-429");
	}
}
