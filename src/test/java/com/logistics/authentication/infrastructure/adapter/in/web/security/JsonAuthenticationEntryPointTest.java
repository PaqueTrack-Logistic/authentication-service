package com.logistics.authentication.infrastructure.adapter.in.web.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import com.fasterxml.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class JsonAuthenticationEntryPointTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonAuthenticationEntryPoint entryPoint = new JsonAuthenticationEntryPoint(objectMapper);

    @Test
    void commence_returns401WithJsonBody() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, new BadCredentialsException("test"));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).isEqualTo("application/json");

        String body = response.getContentAsString();
        assertThat(body).contains("UNAUTHORIZED");
        assertThat(body).contains("Se requiere autenticaci");
    }
}
