package com.logistics.authentication.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.application.port.in.ManageUserRegistrationUseCase.PendingUser;
import com.logistics.authentication.application.port.out.RoleRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;

/**
 * Cobertura de la gestión de aprobaciones: roles asignables, listado de
 * pendientes (con/ sin roles), aprobación (válida, rol inválido, rol no
 * configurado), rechazo y validaciones de estado (no encontrado / no pendiente).
 */
@ExtendWith(MockitoExtension.class)
class ManageUserRegistrationServiceBranchesTest {

	@Mock
	private UserRepositoryPort users;

	@Mock
	private RoleRepositoryPort roles;

	@InjectMocks
	private ManageUserRegistrationService service;

	private UserAccount pending(UUID id, Set<String> roleSet) {
		return UserAccount.builder()
				.id(id).email("p@e.com").passwordHash("h")
				.roles(roleSet).enabled(false)
				.registrationStatus(RegistrationStatus.PENDING)
				.createdAt(Instant.parse("2026-05-01T00:00:00Z"))
				.build();
	}

	@Test
	void listAssignableRoles_returnsSortedRoles() {
		assertThat(service.listAssignableRoles())
				.containsExactly("ROLE_ADMIN", "ROLE_LOGISTICS", "ROLE_OPERATOR");
	}

	@Test
	void listPending_mapsUsersHandlingNullRoles() {
		UserAccount withRoles = pending(UUID.randomUUID(), Set.of("ROLE_OPERATOR"));
		UserAccount nullRoles = pending(UUID.randomUUID(), null);
		when(users.findByRegistrationStatus(RegistrationStatus.PENDING))
				.thenReturn(List.of(withRoles, nullRoles));

		List<PendingUser> result = service.listPending();

		assertThat(result).hasSize(2);
		assertThat(result.get(0).roles()).containsExactly("ROLE_OPERATOR");
		assertThat(result.get(1).roles()).isEmpty();
	}

	@Test
	void approve_validRole_approvesUser() {
		UUID userId = UUID.randomUUID();
		UUID roleId = UUID.randomUUID();
		when(users.findById(userId)).thenReturn(Optional.of(pending(userId, Set.of())));
		when(roles.findRoleIdByName("ROLE_LOGISTICS")).thenReturn(Optional.of(roleId));

		service.approve(userId, "  ROLE_LOGISTICS  ");

		verify(users).approvePendingUser(userId, roleId);
	}

	@Test
	void approve_invalidRole_throws() {
		UUID userId = UUID.randomUUID();
		when(users.findById(userId)).thenReturn(Optional.of(pending(userId, Set.of())));

		assertThatThrownBy(() -> service.approve(userId, "ROLE_HACKER"))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_INVALID_ROLE");

		verify(users, never()).approvePendingUser(any(), any());
	}

	@Test
	void approve_roleNotConfigured_throwsIllegalState() {
		UUID userId = UUID.randomUUID();
		when(users.findById(userId)).thenReturn(Optional.of(pending(userId, Set.of())));
		when(roles.findRoleIdByName("ROLE_ADMIN")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.approve(userId, "ROLE_ADMIN"))
				.isInstanceOf(IllegalStateException.class);

		verify(users, never()).approvePendingUser(any(), any());
	}

	@Test
	void approve_userNotFound_throws() {
		UUID userId = UUID.randomUUID();
		when(users.findById(userId)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> service.approve(userId, "ROLE_OPERATOR"))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_USER_NOT_FOUND");
	}

	@Test
	void approve_userNotPending_throws() {
		UUID userId = UUID.randomUUID();
		UserAccount approved = UserAccount.builder()
				.id(userId).email("a@e.com").passwordHash("h").roles(Set.of("ROLE_OPERATOR"))
				.enabled(true).registrationStatus(RegistrationStatus.APPROVED)
				.createdAt(Instant.parse("2026-05-01T00:00:00Z")).build();
		when(users.findById(userId)).thenReturn(Optional.of(approved));

		assertThatThrownBy(() -> service.approve(userId, "ROLE_OPERATOR"))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_INVALID_REGISTRATION_STATE");
	}

	@Test
	void approve_nullRole_throwsInvalidRole() {
		UUID userId = UUID.randomUUID();
		when(users.findById(userId)).thenReturn(Optional.of(pending(userId, Set.of())));

		assertThatThrownBy(() -> service.approve(userId, null))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_INVALID_ROLE");

		verify(users, never()).approvePendingUser(any(), any());
	}

	@Test
	void reject_pendingUser_marksRejected() {
		UUID userId = UUID.randomUUID();
		when(users.findById(userId)).thenReturn(Optional.of(pending(userId, Set.of())));

		service.reject(userId);

		verify(users).updateRegistrationStatus(userId, RegistrationStatus.REJECTED, false);
	}
}
