package com.logistics.authentication.infrastructure.adapter.out.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordEncoderAdapterTest {

    @Mock
    private PasswordEncoder delegate;

    @InjectMocks
    private PasswordEncoderAdapter adapter;

    @Test
    void matches_returnsTrueForCorrectPassword() {
        when(delegate.matches("rawPass", "encodedPass")).thenReturn(true);

        boolean result = adapter.matches("rawPass", "encodedPass");

        assertThat(result).isTrue();
    }

    @Test
    void matches_returnsFalseForWrongPassword() {
        when(delegate.matches("wrongPass", "encodedPass")).thenReturn(false);

        boolean result = adapter.matches("wrongPass", "encodedPass");

        assertThat(result).isFalse();
    }
}
