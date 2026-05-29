package com.logistics.authentication.infrastructure.adapter.in.web.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.adapter.in.web.filter.TraceIdFilter;

/**
 * Cubre las ramas de resolución de traceId (firstNonBlank): desde MDC y desde
 * la cabecera X-Trace-Id, al construir el 401.
 */
class JsonAuthenticationEntryPointBranchesTest {

	private final JsonAuthenticationEntryPoint entryPoint = new JsonAuthenticationEntryPoint(new ObjectMapper());

	@AfterEach
	void tearDown() {
		MDC.clear();
	}

	@Test
	void commence_usesTraceIdFromMdc() throws Exception {
		MDC.put(TraceIdFilter.TRACE_ID_MDC, "trace-mdc");
		MockHttpServletResponse response = new MockHttpServletResponse();

		entryPoint.commence(new MockHttpServletRequest(), response, new BadCredentialsException("x"));

		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getContentAsString()).contains("trace-mdc");
	}

	@Test
	void commence_usesTraceIdFromHeaderWhenMdcEmpty() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(TraceIdFilter.TRACE_ID_HEADER, "trace-header");
		MockHttpServletResponse response = new MockHttpServletResponse();

		entryPoint.commence(request, response, new BadCredentialsException("x"));

		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getContentAsString()).contains("trace-header");
	}
}
