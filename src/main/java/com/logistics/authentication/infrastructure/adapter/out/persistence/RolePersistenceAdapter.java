package com.logistics.authentication.infrastructure.adapter.out.persistence;

import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.logistics.authentication.application.port.out.RoleRepositoryPort;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.RoleJpaRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class RolePersistenceAdapter implements RoleRepositoryPort {

	private final RoleJpaRepository roleJpaRepository;

	@Override
	public Optional<UUID> findRoleIdByName(String roleName) {
		return roleJpaRepository.findByName(roleName).map(r -> r.getId());
	}
}
