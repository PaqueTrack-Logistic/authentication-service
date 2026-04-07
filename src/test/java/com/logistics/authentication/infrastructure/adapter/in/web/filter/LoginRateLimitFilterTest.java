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

    @Test
    void requestsWithinLimit_passThrough() throws Exception {
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            request.setServletPath("/api/v1/auth/login");
            request.setRemoteAddr("192.168.1.1");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilterInternal(request, response, chain);

            assertThat(response.getStatus()).isNotEqualTo(429);
        }
    }

    @Test
    void requestsExceedingLimit_return429() throws Exception {
        // Exhaust the limit
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            request.setServletPath("/api/v1/auth/login");
            request.setRemoteAddr("10.0.0.1");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            filter.doFilterInternal(request, response, chain);
        }

        // This one should be rate limited
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setServletPath("/api/v1/auth/login");
        request.setRemoteAddr("10.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getContentType()).isEqualTo("application/json");
    }

    @Test
    void getNonLoginRequest_isNotRateLimited() throws Exception {
        for (int i = 0; i < 10; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/me");
            request.setServletPath("/api/v1/auth/me");
            request.setRemoteAddr("10.0.0.2");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilterInternal(request, response, chain);

            assertThat(response.getStatus()).isNotEqualTo(429);
        }
    }

    @Test
    void differentIps_areRateLimitedIndependently() throws Exception {
        // Exhaust limit for IP1
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            request.setServletPath("/api/v1/auth/login");
            request.setRemoteAddr("10.0.0.10");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilterInternal(request, response, new MockFilterChain());
        }

        // IP2 should still work
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setServletPath("/api/v1/auth/login");
        request.setRemoteAddr("10.0.0.20");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilterInternal(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isNotEqualTo(429);
    }
}
