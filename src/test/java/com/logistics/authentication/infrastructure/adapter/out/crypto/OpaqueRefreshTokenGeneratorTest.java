package com.logistics.authentication.infrastructure.adapter.out.crypto;

import java.util.Base64;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OpaqueRefreshTokenGeneratorTest {

    private final OpaqueRefreshTokenGenerator generator = new OpaqueRefreshTokenGenerator();

    @Test
    void generate_returnsNonNullNonBlankToken() {
        String token = generator.generate();

        assertThat(token).isNotNull().isNotBlank();
    }

    @Test
    void generate_returnsBase64UrlEncodedToken() {
        String token = generator.generate();

        // Should decode without exception; URL-safe Base64 without padding
        byte[] decoded = Base64.getUrlDecoder().decode(token);
        assertThat(decoded).hasSize(32);
    }

    @Test
    void generate_producesDifferentTokensOnEachCall() {
        String token1 = generator.generate();
        String token2 = generator.generate();

        assertThat(token1).isNotEqualTo(token2);
    }
}
