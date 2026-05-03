package com.logistics.authentication.infrastructure.adapter.in.web.filter;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.config.SecurityProperties;

class LoginRateLimitFilterTest {

    private LoginRateLimitFilter filter;
    private SecurityProperties securityProperties;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        securityProperties = new SecurityProperties();
        securityProperties.setLoginRateLimitPerMinute(3);
        objectMapper = new ObjectMapper();
        filter = new LoginRateLimitFilter(securityProperties, objectMapper);
    }

    private void executeLoginRequest(String remoteAddr, MockHttpServletResponse response) {
        try {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            request.setServletPath("/api/v1/auth/login");
            request.setRemoteAddr(remoteAddr);
            MockFilterChain chain = new MockFilterChain();
            filter.doFilterInternal(request, response, chain);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void executeRequest(MockHttpServletRequest request, MockHttpServletResponse response) {
        try {
            MockFilterChain chain = new MockFilterChain();
            filter.doFilterInternal(request, response, chain);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void whenLoginRequestsWithinLimit_thenPassThrough() {
        for (int i = 0; i < 3; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            executeLoginRequest("192.168.1.1", response);
            assertThat(response.getStatus()).isNotEqualTo(429);
        }
    }

    @Test
    void whenLoginAttemptsExceedLimit_thenReturn429RateLimited() {
        String testIp = "10.0.0.1";
        // Exhaust the limit
        for (int i = 0; i < 3; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            executeLoginRequest(testIp, response);
        }

        // This one should be rate limited
        MockHttpServletResponse response = new MockHttpServletResponse();
        executeLoginRequest(testIp, response);

        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getContentType()).isEqualTo("application/json");
    }

    @Test
    void whenNonLoginRequest_thenNotRateLimited() {
        for (int i = 0; i < 10; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/me");
            request.setServletPath("/api/v1/auth/me");
            request.setRemoteAddr("10.0.0.2");
            MockHttpServletResponse response = new MockHttpServletResponse();

            executeRequest(request, response);

            assertThat(response.getStatus()).isNotEqualTo(429);
        }
    }

    @Test
    void whenDifferentIpsLogin_thenRateLimitedIndependently() {
        String ip1 = "10.0.0.10";
        String ip2 = "10.0.0.20";

        // Exhaust limit for IP1
        for (int i = 0; i < 3; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            executeLoginRequest(ip1, response);
        }

        // IP2 should still work
        MockHttpServletResponse response = new MockHttpServletResponse();
        executeLoginRequest(ip2, response);

        assertThat(response.getStatus()).isNotEqualTo(429);
    }
}
