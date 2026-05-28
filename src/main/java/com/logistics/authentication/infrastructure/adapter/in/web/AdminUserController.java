package com.logistics.authentication.infrastructure.adapter.in.web;

import java.util.UUID;

import org.springframework.hateoas.EntityModel;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.logistics.authentication.application.port.in.ManageUserRegistrationUseCase;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApproveUserRequest;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.AssignableRolesResponseBody;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.PendingUserResponseBody;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.PendingUserResponseBody.PendingUserItem;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.RegistrationActionResponseBody;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
@Tag(name = "Administración usuarios", description = "Aprobación de registros (ROLE_ADMIN)")
@PreAuthorize("hasRole('ADMIN')")
public class AdminUserController {

	private final ManageUserRegistrationUseCase manageUserRegistrationUseCase;

	@Operation(
			summary = "Roles asignables al aprobar",
			description = "Lista de roles que el administrador puede elegir al aprobar una solicitud.",
			security = @SecurityRequirement(name = "bearer-jwt"))
	@GetMapping(value = "/assignable-roles", produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" })
	public ResponseEntity<EntityModel<AssignableRolesResponseBody>> listAssignableRoles() {
		return ResponseEntity.ok(EntityModel.of(
				new AssignableRolesResponseBody(manageUserRegistrationUseCase.listAssignableRoles())));
	}

	@Operation(
			summary = "Listar solicitudes pendientes",
			description = "Usuarios en estado PENDING esperando aprobación.",
			security = @SecurityRequirement(name = "bearer-jwt"))
	@GetMapping(value = "/pending", produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" })
	public ResponseEntity<EntityModel<PendingUserResponseBody>> listPending() {
		var items = manageUserRegistrationUseCase.listPending().stream()
				.map(u -> new PendingUserItem(u.id(), u.email(), u.createdAt(), u.roles()))
				.toList();
		return ResponseEntity.ok(EntityModel.of(new PendingUserResponseBody(items)));
	}

	@Operation(
			summary = "Aprobar registro",
			description = "Activa la cuenta (APPROVED), asigna el rol indicado y permite login.",
			security = @SecurityRequirement(name = "bearer-jwt"))
	@PostMapping(value = "/{userId}/approve", produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" })
	public ResponseEntity<EntityModel<RegistrationActionResponseBody>> approve(
			@PathVariable UUID userId,
			@Valid @RequestBody ApproveUserRequest request) {
		manageUserRegistrationUseCase.approve(userId, request.role());
		return ResponseEntity.ok(EntityModel.of(new RegistrationActionResponseBody(
				userId,
				"APPROVED",
				"Usuario aprobado con rol " + request.role() + "; ya puede iniciar sesión")));
	}

	@Operation(
			summary = "Rechazar registro",
			description = "Marca la solicitud como REJECTED.",
			security = @SecurityRequirement(name = "bearer-jwt"))
	@PostMapping(value = "/{userId}/reject", produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" })
	public ResponseEntity<EntityModel<RegistrationActionResponseBody>> reject(@PathVariable UUID userId) {
		manageUserRegistrationUseCase.reject(userId);
		return ResponseEntity.ok(EntityModel.of(new RegistrationActionResponseBody(
				userId, "REJECTED", "Solicitud rechazada")));
	}
}
