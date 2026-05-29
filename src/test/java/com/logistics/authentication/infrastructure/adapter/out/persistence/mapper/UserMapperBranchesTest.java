package com.logistics.authentication.infrastructure.adapter.out.persistence.mapper;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.RoleEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.UserEntity;

/**
 * Cubre parseStatus: estado nulo/en blanco -> APPROVED (default) vs estado
 * explícito parseado, y el mapeo de roles.
 */
class UserMapperBranchesTest {

	private final UserMapper mapper = new UserMapper();

	private UserEntity entityWithStatus(String status) {
		UserEntity e = new UserEntity();
		e.setId(UUID.randomUUID());
		e.setEmail("u@e.com");
		e.setPasswordHash("hash");
		e.setEnabled(true);
		e.setFailedLoginAttempts(0);
		RoleEntity role = new RoleEntity();
		role.setName("ROLE_ADMIN");
		e.setRoles(new HashSet<>(Set.of(role)));
		e.setRegistrationStatus(status);
		return e;
	}

	@Test
	void toDomain_nullStatus_defaultsToApproved() {
		UserAccount domain = mapper.toDomain(entityWithStatus(null));
		assertThat(domain.getRegistrationStatus()).isEqualTo(RegistrationStatus.APPROVED);
		assertThat(domain.getRoles()).containsExactly("ROLE_ADMIN");
	}

	@Test
	void toDomain_blankStatus_defaultsToApproved() {
		UserAccount domain = mapper.toDomain(entityWithStatus("   "));
		assertThat(domain.getRegistrationStatus()).isEqualTo(RegistrationStatus.APPROVED);
	}

	@Test
	void toDomain_explicitStatus_isParsed() {
		UserAccount domain = mapper.toDomain(entityWithStatus("PENDING"));
		assertThat(domain.getRegistrationStatus()).isEqualTo(RegistrationStatus.PENDING);
	}
}
