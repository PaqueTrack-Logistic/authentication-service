package com.logistics.authentication.infrastructure.adapter.out.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.infrastructure.adapter.out.crypto.OpaqueRefreshTokenGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenIssuerAdapterTest {

    @Mock
    private OpaqueRefreshTokenGenerator generator;

    @InjectMocks
    private RefreshTokenIssuerAdapter adapter;

    @Test
    void newOpaqueToken_delegatesToGenerator() {
        when(generator.generate()).thenReturn("opaque-token-value");

        String result = adapter.newOpaqueToken();

        assertThat(result).isEqualTo("opaque-token-value");
        verify(generator).generate();
    }

    @Test
    void sha256Hex_delegatesToSha256HexUtility() {
        // Sha256Hex is a static utility, so we verify correctness by checking output
        String result = adapter.sha256Hex("test-token");

        assertThat(result).isNotNull().hasSize(64);
        // Should be consistent
        assertThat(result).isEqualTo(adapter.sha256Hex("test-token"));
    }
}
