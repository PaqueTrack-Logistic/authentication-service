package com.logistics.authentication.infrastructure.adapter.out.persistence.mapper;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.RoleEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.UserEntity;

class UserMapperTest {

    private final UserMapper mapper = new UserMapper();

    @Test
    void toDomain_mapsEntityWithRolesCorrectly() {
        UUID userId = UUID.randomUUID();
        UserEntity entity = new UserEntity();
        entity.setId(userId);
        entity.setEmail("admin@logistics.com");
        entity.setPasswordHash("$2a$10$hashedpassword");
        entity.setEnabled(true);
        entity.setFailedLoginAttempts(2);
        entity.setLockedUntil(Instant.parse("2026-12-31T23:59:59Z"));

        RoleEntity role1 = new RoleEntity();
        role1.setId(UUID.randomUUID());
        role1.setName("ROLE_ADMIN");

        RoleEntity role2 = new RoleEntity();
        role2.setId(UUID.randomUUID());
        role2.setName("ROLE_USER");

        entity.setRoles(Set.of(role1, role2));

        UserAccount domain = mapper.toDomain(entity);

        assertThat(domain.getId()).isEqualTo(userId);
        assertThat(domain.getEmail()).isEqualTo("admin@logistics.com");
        assertThat(domain.getPasswordHash()).isEqualTo("$2a$10$hashedpassword");
        assertThat(domain.isEnabled()).isTrue();
        assertThat(domain.getFailedLoginAttempts()).isEqualTo(2);
        assertThat(domain.getLockedUntil()).isEqualTo(Instant.parse("2026-12-31T23:59:59Z"));
        assertThat(domain.getRoles()).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    void toDomain_mapsEntityWithEmptyRoles() {
        UserEntity entity = new UserEntity();
        entity.setId(UUID.randomUUID());
        entity.setEmail("noroles@test.com");
        entity.setPasswordHash("hash");
        entity.setEnabled(true);
        entity.setFailedLoginAttempts(0);
        entity.setLockedUntil(null);
        entity.setRoles(new HashSet<>());

        UserAccount domain = mapper.toDomain(entity);

        assertThat(domain.getRoles()).isEmpty();
        assertThat(domain.getLockedUntil()).isNull();
    }

    @Test
    void toDomain_mapsDisabledUser() {
        UserEntity entity = new UserEntity();
        entity.setId(UUID.randomUUID());
        entity.setEmail("disabled@test.com");
        entity.setPasswordHash("hash");
        entity.setEnabled(false);
        entity.setFailedLoginAttempts(5);
        entity.setLockedUntil(null);
        entity.setRoles(new HashSet<>());

        UserAccount domain = mapper.toDomain(entity);

        assertThat(domain.isEnabled()).isFalse();
        assertThat(domain.getFailedLoginAttempts()).isEqualTo(5);
    }
}
