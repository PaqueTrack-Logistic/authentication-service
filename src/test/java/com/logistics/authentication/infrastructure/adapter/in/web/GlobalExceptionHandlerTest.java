package com.logistics.authentication.infrastructure.adapter.in.web;

import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class GlobalExceptionHandlerTest {

    private MockMvc mockMvc;

    @RestController
    static class FakeController {

        @GetMapping("/fake/auth-domain-unauthorized")
        public void throwAuthDomainUnauthorized() {
            throw new AuthenticationDomainException("AUTH_INVALID_CREDENTIALS", "Credenciales inválidas");
        }

        @GetMapping("/fake/auth-domain-locked")
        public void throwAuthDomainLocked() {
            throw new AuthenticationDomainException("AUTH_ACCOUNT_LOCKED", "Cuenta bloqueada");
        }

        @GetMapping("/fake/auth-domain-disabled")
        public void throwAuthDomainDisabled() {
            throw new AuthenticationDomainException("AUTH_ACCOUNT_DISABLED", "Cuenta deshabilitada");
        }

        @GetMapping("/fake/access-denied")
        public void throwAccessDenied() {
            throw new AccessDeniedException("No tiene permisos");
        }

        @PostMapping("/fake/validation")
        public void throwValidation(@Valid @RequestBody ValidationDto dto) {
            // If reached, validation passed (should not happen in test)
        }

        @GetMapping("/fake/generic")
        public void throwGeneric() {
            throw new RuntimeException("Something unexpected");
        }
    }

    record ValidationDto(@NotBlank String name) {}

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new FakeController())
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void handleAuthDomain_defaultErrorCode_returns401() throws Exception {
        mockMvc.perform(get("/fake/auth-domain-unauthorized"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("AUTH_INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("Credenciales inválidas"));
    }

    @Test
    void handleAuthDomain_accountLocked_returns403() throws Exception {
        mockMvc.perform(get("/fake/auth-domain-locked"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("AUTH_ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.message").value("Cuenta bloqueada"));
    }

    @Test
    void handleAuthDomain_accountDisabled_returns403() throws Exception {
        mockMvc.perform(get("/fake/auth-domain-disabled"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("AUTH_ACCOUNT_DISABLED"))
                .andExpect(jsonPath("$.message").value("Cuenta deshabilitada"));
    }

    @Test
    void handleAccessDenied_returns403() throws Exception {
        mockMvc.perform(get("/fake/access-denied"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ACCESS_DENIED"))
                .andExpect(jsonPath("$.message").value("Permisos insuficientes para este recurso"));
    }

    @Test
    void handleValidation_returns400WithDetails() throws Exception {
        mockMvc.perform(post("/fake/validation")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.message").value("Payload inválido"))
                .andExpect(jsonPath("$.details").isArray())
                .andExpect(jsonPath("$.details").isNotEmpty());
    }

    @Test
    void handleGeneric_returns500() throws Exception {
        mockMvc.perform(get("/fake/generic"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("INTERNAL_ERROR"))
                .andExpect(jsonPath("$.message").value("Error interno"));
    }
}
