package com.logistics.authentication.infrastructure.adapter.in.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.hateoas.EntityModel;

import com.logistics.authentication.application.port.in.ManageUserRegistrationUseCase;
import com.logistics.authentication.application.port.in.ManageUserRegistrationUseCase.PendingUser;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApproveUserRequest;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.AssignableRolesResponseBody;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.PendingUserResponseBody;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.RegistrationActionResponseBody;

/**
 * Cubre los 4 endpoints del controlador de administración de usuarios
 * (assignable-roles, pending, approve, reject) mockeando el caso de uso.
 */
@ExtendWith(MockitoExtension.class)
class AdminUserControllerTest {

	@Mock
	private ManageUserRegistrationUseCase manageUserRegistrationUseCase;

	@InjectMocks
	private AdminUserController controller;

	@Test
	void listAssignableRoles_returnsRolesFromUseCase() {
		when(manageUserRegistrationUseCase.listAssignableRoles())
				.thenReturn(List.of("ROLE_OPERATOR", "ROLE_LOGISTICS"));

		var response = controller.listAssignableRoles();

		assertThat(response.getStatusCode().value()).isEqualTo(200);
		AssignableRolesResponseBody body = response.getBody().getContent();
		assertThat(body).isNotNull();
		assertThat(body.roles()).containsExactly("ROLE_OPERATOR", "ROLE_LOGISTICS");
	}

	@Test
	void listPending_mapsPendingUsers() {
		PendingUser pending = new PendingUser(
				UUID.randomUUID(), "pending@e.com", Instant.now(), List.of("ROLE_OPERATOR"));
		when(manageUserRegistrationUseCase.listPending()).thenReturn(List.of(pending));

		var response = controller.listPending();

		assertThat(response.getStatusCode().value()).isEqualTo(200);
		EntityModel<PendingUserResponseBody> body = response.getBody();
		assertThat(body).isNotNull();
		assertThat(body.getContent().users()).hasSize(1);
		verify(manageUserRegistrationUseCase).listPending();
	}

	@Test
	void approve_delegatesAndReturnsApproved() {
		UUID userId = UUID.randomUUID();

		var response = controller.approve(userId, new ApproveUserRequest("ROLE_OPERATOR"));

		verify(manageUserRegistrationUseCase).approve(userId, "ROLE_OPERATOR");
		assertThat(response.getStatusCode().value()).isEqualTo(200);
		RegistrationActionResponseBody body = response.getBody().getContent();
		assertThat(body.status()).isEqualTo("APPROVED");
		assertThat(body.userId()).isEqualTo(userId);
	}

	@Test
	void reject_delegatesAndReturnsRejected() {
		UUID userId = UUID.randomUUID();

		var response = controller.reject(userId);

		verify(manageUserRegistrationUseCase).reject(userId);
		assertThat(response.getStatusCode().value()).isEqualTo(200);
		RegistrationActionResponseBody body = response.getBody().getContent();
		assertThat(body.status()).isEqualTo("REJECTED");
		assertThat(body.userId()).isEqualTo(userId);
	}
}
