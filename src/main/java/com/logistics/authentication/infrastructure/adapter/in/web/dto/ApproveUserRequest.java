package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@Schema(description = "Aprobación de registro con rol asignado por el administrador")
public record ApproveUserRequest(
		@NotBlank
		@Pattern(regexp = "^ROLE_(OPERATOR|ADMIN|LOGISTICS)$", message = "Rol debe ser ROLE_OPERATOR, ROLE_ADMIN o ROLE_LOGISTICS")
		@Schema(example = "ROLE_OPERATOR", description = "Rol que tendrá el usuario tras la aprobación")
		String role) {
}
