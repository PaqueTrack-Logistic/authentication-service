package com.logistics.authentication.infrastructure.adapter.out.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.RoleEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.RoleJpaRepository;

/**
 * Cubre la resolución de id de rol por nombre (encontrado / no encontrado).
 */
@ExtendWith(MockitoExtension.class)
class RolePersistenceAdapterTest {

	@Mock
	private RoleJpaRepository roleJpaRepository;

	@InjectMocks
	private RolePersistenceAdapter adapter;

	@Test
	void findRoleIdByName_returnsIdWhenRoleExists() {
		UUID id = UUID.randomUUID();
		RoleEntity role = new RoleEntity();
		role.setId(id);
		when(roleJpaRepository.findByName("ROLE_OPERATOR")).thenReturn(Optional.of(role));

		assertThat(adapter.findRoleIdByName("ROLE_OPERATOR")).contains(id);
	}

	@Test
	void findRoleIdByName_returnsEmptyWhenRoleMissing() {
		when(roleJpaRepository.findByName("ROLE_GHOST")).thenReturn(Optional.empty());

		assertThat(adapter.findRoleIdByName("ROLE_GHOST")).isEmpty();
	}
}
