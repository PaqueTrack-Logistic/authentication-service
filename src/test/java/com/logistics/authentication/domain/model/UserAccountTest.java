package com.logistics.authentication.domain.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

class UserAccountTest {

    @Test
    void isLocked_returnsTrueWhenLockedUntilIsInTheFuture() {
        Instant now = Instant.parse("2026-01-15T10:00:00Z");
        UserAccount user = UserAccount.builder()
                .id(UUID.randomUUID())
                .email("locked@test.com")
                .passwordHash("hash")
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .failedLoginAttempts(5)
                .lockedUntil(now.plusSeconds(300))
                .build();

        assertThat(user.isLocked(now)).isTrue();
    }

    @Test
    void isLocked_returnsFalseWhenLockedUntilIsInThePast() {
        Instant now = Instant.parse("2026-01-15T10:00:00Z");
        UserAccount user = UserAccount.builder()
                .id(UUID.randomUUID())
                .email("unlocked@test.com")
                .passwordHash("hash")
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .failedLoginAttempts(5)
                .lockedUntil(now.minusSeconds(300))
                .build();

        assertThat(user.isLocked(now)).isFalse();
    }

    @Test
    void isLocked_returnsFalseWhenLockedUntilIsNull() {
        Instant now = Instant.parse("2026-01-15T10:00:00Z");
        UserAccount user = UserAccount.builder()
                .id(UUID.randomUUID())
                .email("normal@test.com")
                .passwordHash("hash")
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .failedLoginAttempts(0)
                .lockedUntil(null)
                .build();

        assertThat(user.isLocked(now)).isFalse();
    }

    @Test
    void isLocked_returnsFalseWhenLockedUntilEqualsNow() {
        Instant now = Instant.parse("2026-01-15T10:00:00Z");
        UserAccount user = UserAccount.builder()
                .id(UUID.randomUUID())
                .email("edge@test.com")
                .passwordHash("hash")
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .failedLoginAttempts(3)
                .lockedUntil(now)
                .build();

        assertThat(user.isLocked(now)).isFalse();
    }
}
