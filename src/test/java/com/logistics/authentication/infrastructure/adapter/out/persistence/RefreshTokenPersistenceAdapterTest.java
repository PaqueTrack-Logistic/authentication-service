package com.logistics.authentication.infrastructure.adapter.out.persistence;

import com.logistics.authentication.application.port.out.RefreshTokenRepositoryPort.RefreshTokenActive;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.RefreshTokenEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.RefreshTokenJpaRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenPersistenceAdapterTest {

    @Mock
    private RefreshTokenJpaRepository jpaRepository;

    @Mock
    private Clock clock;

    @InjectMocks
    private RefreshTokenPersistenceAdapter adapter;

    @Test
    void save_persistsTokenAndReturnsId() {
        UUID userId = UUID.randomUUID();
        String hash = "abc123hash";
        Instant expiresAt = Instant.now().plusSeconds(3600);
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        when(clock.instant()).thenReturn(now);

        ArgumentCaptor<RefreshTokenEntity> captor = ArgumentCaptor.forClass(RefreshTokenEntity.class);
        when(jpaRepository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        UUID result = adapter.save(userId, hash, expiresAt);

        assertThat(result).isNotNull();
        RefreshTokenEntity saved = captor.getValue();
        assertThat(saved.getUserId()).isEqualTo(userId);
        assertThat(saved.getTokenHash()).isEqualTo(hash);
        assertThat(saved.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(saved.getCreatedAt()).isEqualTo(now);
    }

    @Test
    void findActiveByTokenHash_returnsMappedResult() {
        UUID tokenId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        Instant now = Instant.now();

        RefreshTokenEntity entity = RefreshTokenEntity.create(
                tokenId, userId, "hash", now.plusSeconds(3600), now);
        when(jpaRepository.findActiveByHash("hash", now)).thenReturn(Optional.of(entity));

        Optional<RefreshTokenActive> result = adapter.findActiveByTokenHash("hash", now);

        assertThat(result).isPresent();
        assertThat(result.get().id()).isEqualTo(tokenId);
        assertThat(result.get().userId()).isEqualTo(userId);
    }

    @Test
    void findActiveByTokenHash_returnsEmptyWhenNotFound() {
        Instant now = Instant.now();
        when(jpaRepository.findActiveByHash("missing", now)).thenReturn(Optional.empty());

        Optional<RefreshTokenActive> result = adapter.findActiveByTokenHash("missing", now);

        assertThat(result).isEmpty();
    }

    @Test
    void revokeAllForUser_delegatesToRepository() {
        UUID userId = UUID.randomUUID();

        adapter.revokeAllForUser(userId);

        verify(jpaRepository).revokeAllActiveByUserId(userId);
    }
}
