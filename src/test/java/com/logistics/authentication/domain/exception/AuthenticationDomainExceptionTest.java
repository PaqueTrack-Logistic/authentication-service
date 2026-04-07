package com.logistics.authentication.domain.exception;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthenticationDomainExceptionTest {

    @Test
    void constructorSetsErrorCodeAndMessage() {
        AuthenticationDomainException ex = new AuthenticationDomainException(
                "AUTH_INVALID_CREDENTIALS", "Credenciales incorrectas");

        assertThat(ex.getErrorCode()).isEqualTo("AUTH_INVALID_CREDENTIALS");
        assertThat(ex.getMessage()).isEqualTo("Credenciales incorrectas");
    }

    @Test
    void exceptionIsRuntimeException() {
        AuthenticationDomainException ex = new AuthenticationDomainException(
                "SOME_CODE", "some message");

        assertThat(ex).isInstanceOf(RuntimeException.class);
    }

    @Test
    void differentErrorCodesAreStoredCorrectly() {
        AuthenticationDomainException locked = new AuthenticationDomainException(
                "AUTH_ACCOUNT_LOCKED", "Cuenta bloqueada temporalmente");
        AuthenticationDomainException disabled = new AuthenticationDomainException(
                "AUTH_ACCOUNT_DISABLED", "Cuenta deshabilitada");

        assertThat(locked.getErrorCode()).isEqualTo("AUTH_ACCOUNT_LOCKED");
        assertThat(locked.getMessage()).isEqualTo("Cuenta bloqueada temporalmente");
        assertThat(disabled.getErrorCode()).isEqualTo("AUTH_ACCOUNT_DISABLED");
        assertThat(disabled.getMessage()).isEqualTo("Cuenta deshabilitada");
    }
}
