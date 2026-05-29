package com.logistics.authentication.infrastructure.adapter.out.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.RoleEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.UserEntity;
import com.logistics.authentication.infrastructure.adapter.out.persistence.mapper.UserMapper;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.RoleJpaRepository;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.UserJpaRepository;

/**
 * Cubre los métodos del adapter no ejercitados por el test base: findById,
 * existsByEmail, savePendingUser, approvePendingUser (incluidas las ramas
 * orElseThrow), findByRegistrationStatus y updateRegistrationStatus.
 */
@ExtendWith(MockitoExtension.class)
class UserPersistenceAdapterBranchesTest {

	@Mock
	private UserJpaRepository userJpaRepository;

	@Mock
	private RoleJpaRepository roleJpaRepository;

	@Mock
	private UserMapper userMapper;

	@InjectMocks
	private UserPersistenceAdapter adapter;

	@Test
	void findById_returnsMappedDomainUser() {
		UUID id = UUID.randomUUID();
		UserEntity entity = new UserEntity();
		entity.setId(id);
		UserAccount domain = UserAccount.builder().id(id).email("u@e.com").build();
		when(userJpaRepository.findById(id)).thenReturn(Optional.of(entity));
		when(userMapper.toDomain(entity)).thenReturn(domain);

		assertThat(adapter.findById(id)).contains(domain);
	}

	@Test
	void findById_returnsEmptyWhenNotFound() {
		UUID id = UUID.randomUUID();
		when(userJpaRepository.findById(id)).thenReturn(Optional.empty());

		assertThat(adapter.findById(id)).isEmpty();
	}

	@Test
	void existsByEmail_delegatesToRepository() {
		when(userJpaRepository.existsByEmailIgnoreCase("a@e.com")).thenReturn(true);
		when(userJpaRepository.existsByEmailIgnoreCase("b@e.com")).thenReturn(false);

		assertThat(adapter.existsByEmail("a@e.com")).isTrue();
		assertThat(adapter.existsByEmail("b@e.com")).isFalse();
	}

	@Test
	void savePendingUser_buildsPendingEntityAndSaves() {
		UUID id = UUID.randomUUID();
		UUID roleId = UUID.randomUUID();
		when(roleJpaRepository.findById(roleId)).thenReturn(Optional.of(new RoleEntity()));

		adapter.savePendingUser(id, "new@e.com", "hashed", roleId);

		ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);
		verify(userJpaRepository).save(captor.capture());
		UserEntity saved = captor.getValue();
		assertThat(saved.getId()).isEqualTo(id);
		assertThat(saved.getEmail()).isEqualTo("new@e.com");
		assertThat(saved.getPasswordHash()).isEqualTo("hashed");
		assertThat(saved.isEnabled()).isFalse();
		assertThat(saved.getRegistrationStatus()).isEqualTo(RegistrationStatus.PENDING.name());
		assertThat(saved.getFailedLoginAttempts()).isZero();
		assertThat(saved.getLockedUntil()).isNull();
		assertThat(saved.getRoles()).hasSize(1);
	}

	@Test
	void savePendingUser_throwsWhenRoleNotFound() {
		UUID roleId = UUID.randomUUID();
		when(roleJpaRepository.findById(roleId)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> adapter.savePendingUser(UUID.randomUUID(), "x@e.com", "h", roleId))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Rol no encontrado");
		verify(userJpaRepository, never()).save(any());
	}

	@Test
	void findByRegistrationStatus_mapsResults() {
		UserEntity entity = new UserEntity();
		UserAccount domain = UserAccount.builder().id(UUID.randomUUID()).email("p@e.com").build();
		when(userJpaRepository.findByRegistrationStatusOrderByCreatedAtAsc("PENDING"))
				.thenReturn(List.of(entity));
		when(userMapper.toDomain(entity)).thenReturn(domain);

		List<UserAccount> result = adapter.findByRegistrationStatus(RegistrationStatus.PENDING);

		assertThat(result).containsExactly(domain);
	}

	@Test
	void updateRegistrationStatus_delegatesWithTimestamp() {
		UUID id = UUID.randomUUID();

		adapter.updateRegistrationStatus(id, RegistrationStatus.APPROVED, true);

		verify(userJpaRepository).updateRegistrationStatus(eq(id), eq("APPROVED"), eq(true), any(Instant.class));
	}

	@Test
	void approvePendingUser_setsApprovedEnabledAndRole() {
		UUID userId = UUID.randomUUID();
		UUID roleId = UUID.randomUUID();
		UserEntity entity = new UserEntity();
		entity.setId(userId);
		entity.setEnabled(false);
		entity.setRegistrationStatus(RegistrationStatus.PENDING.name());
		when(userJpaRepository.findById(userId)).thenReturn(Optional.of(entity));
		when(roleJpaRepository.findById(roleId)).thenReturn(Optional.of(new RoleEntity()));

		adapter.approvePendingUser(userId, roleId);

		ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);
		verify(userJpaRepository).save(captor.capture());
		UserEntity saved = captor.getValue();
		assertThat(saved.getRegistrationStatus()).isEqualTo(RegistrationStatus.APPROVED.name());
		assertThat(saved.isEnabled()).isTrue();
		assertThat(saved.getRoles()).hasSize(1);
	}

	@Test
	void approvePendingUser_throwsWhenUserNotFound() {
		UUID userId = UUID.randomUUID();
		when(userJpaRepository.findById(userId)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> adapter.approvePendingUser(userId, UUID.randomUUID()))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Usuario no encontrado");
		verify(userJpaRepository, never()).save(any());
	}

	@Test
	void approvePendingUser_throwsWhenRoleNotFound() {
		UUID userId = UUID.randomUUID();
		UUID roleId = UUID.randomUUID();
		when(userJpaRepository.findById(userId)).thenReturn(Optional.of(new UserEntity()));
		when(roleJpaRepository.findById(roleId)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> adapter.approvePendingUser(userId, roleId))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Rol no encontrado");
		verify(userJpaRepository, never()).save(any());
	}
}
