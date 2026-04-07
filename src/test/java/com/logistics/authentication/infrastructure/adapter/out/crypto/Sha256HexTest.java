package com.logistics.authentication.infrastructure.adapter.out.crypto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Sha256HexTest {

    @Test
    void of_returnsConsistentHashForSameInput() {
        String hash1 = Sha256Hex.of("hello");
        String hash2 = Sha256Hex.of("hello");

        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void of_returnsDifferentHashesForDifferentInputs() {
        String hash1 = Sha256Hex.of("hello");
        String hash2 = Sha256Hex.of("world");

        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    void of_returns64CharHexString() {
        String hash = Sha256Hex.of("test-input");

        assertThat(hash).hasSize(64);
        assertThat(hash).matches("[0-9a-f]{64}");
    }
}
