package com.logistics.authentication.infrastructure.adapter.out.persistence;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.RoleEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.UserEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.mapper.UserMapper;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.RoleJpaRepository;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.UserJpaRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class UserPersistenceAdapter implements UserRepositoryPort {

	private final UserJpaRepository userJpaRepository;
	private final RoleJpaRepository roleJpaRepository;
	private final UserMapper userMapper;

	@Override
	public Optional<UserAccount> findByEmail(String email) {
		return userJpaRepository.findByEmailIgnoreCase(email).map(userMapper::toDomain);
	}

	@Override
	public Optional<UserAccount> findById(UUID id) {
		return userJpaRepository.findById(id).map(userMapper::toDomain);
	}

	@Override
	public boolean existsByEmail(String email) {
		return userJpaRepository.existsByEmailIgnoreCase(email);
	}

	@Override
	public void savePendingUser(UUID id, String email, String passwordHash, UUID operatorRoleId) {
		RoleEntity role = roleJpaRepository.findById(operatorRoleId)
				.orElseThrow(() -> new IllegalArgumentException("Rol no encontrado: " + operatorRoleId));
		UserEntity entity = new UserEntity();
		entity.setId(id);
		entity.setEmail(email);
		entity.setPasswordHash(passwordHash);
		entity.setEnabled(false);
		entity.setRegistrationStatus(RegistrationStatus.PENDING.name());
		entity.setFailedLoginAttempts(0);
		entity.setLockedUntil(null);
		entity.setRoles(new HashSet<>(List.of(role)));
		userJpaRepository.save(entity);
	}

	@Override
	public List<UserAccount> findByRegistrationStatus(RegistrationStatus status) {
		return userJpaRepository.findByRegistrationStatusOrderByCreatedAtAsc(status.name()).stream()
				.map(userMapper::toDomain)
				.toList();
	}

	@Override
	public void updateRegistrationStatus(UUID userId, RegistrationStatus status, boolean enabled) {
		userJpaRepository.updateRegistrationStatus(userId, status.name(), enabled);
	}

	@Override
	public void approvePendingUser(UUID userId, UUID roleId) {
		UserEntity user = userJpaRepository.findById(userId)
				.orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado: " + userId));
		RoleEntity role = roleJpaRepository.findById(roleId)
				.orElseThrow(() -> new IllegalArgumentException("Rol no encontrado: " + roleId));
		user.setRoles(new HashSet<>(List.of(role)));
		user.setRegistrationStatus(RegistrationStatus.APPROVED.name());
		user.setEnabled(true);
		userJpaRepository.save(user);
	}

	@Override
	public void resetFailedLogin(UUID userId) {
		userJpaRepository.resetFailedLogin(userId);
	}

	@Override
	public void registerFailedLogin(UUID userId, int newAttemptCount, java.time.Instant lockedUntilOrNull) {
		userJpaRepository.updateFailedLogin(userId, newAttemptCount, lockedUntilOrNull);
	}
}
