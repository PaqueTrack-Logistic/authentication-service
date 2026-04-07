package com.logistics.authentication.infrastructure.adapter.in.web;

import com.logistics.authentication.application.port.in.LoginUseCase;
import com.logistics.authentication.application.port.in.LoginUseCase.LoginResult;
import com.logistics.authentication.application.port.in.RefreshTokenUseCase;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.infrastructure.adapter.in.web.security.JwtPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private LoginUseCase loginUseCase;

    @Mock
    private RefreshTokenUseCase refreshTokenUseCase;

    @InjectMocks
    private AuthController authController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void login_returns200AndBody() throws Exception {
        when(loginUseCase.login(any()))
                .thenReturn(new LoginResult("tok", "Bearer", 3600, Set.of("ROLE_ADMIN"), "refresh-opaque", 604800L));

        String body = "{\"email\":\"admin@logistics.com\",\"password\":\"password123\"}";

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("tok"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andExpect(jsonPath("$.refreshToken").value("refresh-opaque"))
                .andExpect(jsonPath("$.refreshExpiresIn").value(604800));
    }

    @Test
    void refresh_returns200AndNewTokens() throws Exception {
        when(refreshTokenUseCase.refresh(any()))
                .thenReturn(new LoginResult("new-access", "Bearer", 3600, Set.of("ROLE_USER"), "new-refresh", 604800L));

        String body = "{\"refreshToken\":\"old-refresh-token\"}";

        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void me_returns200WhenAuthenticated() throws Exception {
        JwtPrincipal principal = new JwtPrincipal("33333333-3333-3333-3333-333333333333", "admin@logistics.com");
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        var auth = new UsernamePasswordAuthenticationToken(principal, null, authorities);

        mockMvc.perform(get("/api/v1/auth/me")
                .principal(auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("33333333-3333-3333-3333-333333333333"))
                .andExpect(jsonPath("$.email").value("admin@logistics.com"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_ADMIN"));
    }

    @Test
    void me_returns401WhenNotAuthenticated() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_returns401WhenDomainExceptionThrown() throws Exception {
        when(loginUseCase.login(any()))
                .thenThrow(new AuthenticationDomainException("AUTH_INVALID_CREDENTIALS", "Credenciales incorrectas"));

        String body = "{\"email\":\"admin@logistics.com\",\"password\":\"wrongpassword\"}";

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("AUTH_INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("Credenciales incorrectas"));
    }

    @Test
    void login_returns400WhenRequestBodyIsInvalid() throws Exception {
        String invalidBody = "{\"email\":\"\",\"password\":\"\"}";

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    void refresh_returns400WhenRefreshTokenIsBlank() throws Exception {
        String invalidBody = "{\"refreshToken\":\"\"}";

        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidBody))
                .andExpect(status().isBadRequest());
    }
}
