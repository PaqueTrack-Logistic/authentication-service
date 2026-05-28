package com.logistics.authentication.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.application.port.out.RoleRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;

@ExtendWith(MockitoExtension.class)
class ManageUserRegistrationServiceTest {

	private static final UUID USER_ID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
	private static final UUID OPERATOR_ROLE_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");

	@Mock
	private UserRepositoryPort users;

	@Mock
	private RoleRepositoryPort roles;

	@InjectMocks
	private ManageUserRegistrationService service;

	@Test
	void listAssignableRoles_returnsOperatorAdminAndLogistics() {
		assertThat(service.listAssignableRoles()).containsExactly("ROLE_ADMIN", "ROLE_LOGISTICS", "ROLE_OPERATOR");
	}

	@Test
	void approve_assignsRoleAndActivatesUser() {
		when(users.findById(USER_ID)).thenReturn(Optional.of(pendingUser()));
		when(roles.findRoleIdByName("ROLE_OPERATOR")).thenReturn(Optional.of(OPERATOR_ROLE_ID));

		service.approve(USER_ID, "ROLE_OPERATOR");

		verify(users).approvePendingUser(USER_ID, OPERATOR_ROLE_ID);
	}

	@Test
	void approve_rejectsUnknownRole() {
		when(users.findById(USER_ID)).thenReturn(Optional.of(pendingUser()));

		assertThatThrownBy(() -> service.approve(USER_ID, "ROLE_GUEST"))
				.isInstanceOf(AuthenticationDomainException.class)
				.hasMessageContaining("Rol no permitido");
	}

	private static UserAccount pendingUser() {
		return UserAccount.builder()
				.id(USER_ID)
				.email("pending@test.com")
				.passwordHash("hash")
				.roles(Set.of("ROLE_OPERATOR"))
				.enabled(false)
				.registrationStatus(RegistrationStatus.PENDING)
				.createdAt(Instant.parse("2026-05-21T10:00:00Z"))
				.build();
	}
}
