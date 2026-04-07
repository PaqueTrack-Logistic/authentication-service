package com.logistics.authentication.infrastructure.adapter.out.persistence;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.UserEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.mapper.UserMapper;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.UserJpaRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserPersistenceAdapterTest {

    @Mock
    private UserJpaRepository userJpaRepository;

    @Mock
    private UserMapper userMapper;

    @InjectMocks
    private UserPersistenceAdapter adapter;

    @Test
    void findByEmail_returnsMappedDomainUser() {
        UserEntity entity = new UserEntity();
        entity.setId(UUID.randomUUID());
        entity.setEmail("user@example.com");

        UserAccount domainUser = UserAccount.builder()
                .id(entity.getId())
                .email("user@example.com")
                .passwordHash("hashed")
                .roles(Set.of("ADMIN"))
                .enabled(true)
                .failedLoginAttempts(0)
                .build();

        when(userJpaRepository.findByEmailIgnoreCase("user@example.com")).thenReturn(Optional.of(entity));
        when(userMapper.toDomain(entity)).thenReturn(domainUser);

        Optional<UserAccount> result = adapter.findByEmail("user@example.com");

        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("user@example.com");
        verify(userJpaRepository).findByEmailIgnoreCase("user@example.com");
        verify(userMapper).toDomain(entity);
    }

    @Test
    void findByEmail_returnsEmptyWhenNotFound() {
        when(userJpaRepository.findByEmailIgnoreCase("unknown@example.com")).thenReturn(Optional.empty());

        Optional<UserAccount> result = adapter.findByEmail("unknown@example.com");

        assertThat(result).isEmpty();
    }

    @Test
    void resetFailedLogin_delegatesToRepository() {
        UUID userId = UUID.randomUUID();

        adapter.resetFailedLogin(userId);

        verify(userJpaRepository).resetFailedLogin(userId);
    }

    @Test
    void registerFailedLogin_delegatesToRepository() {
        UUID userId = UUID.randomUUID();
        Instant lockedUntil = Instant.now().plusSeconds(300);

        adapter.registerFailedLogin(userId, 3, lockedUntil);

        verify(userJpaRepository).updateFailedLogin(userId, 3, lockedUntil);
    }
}
