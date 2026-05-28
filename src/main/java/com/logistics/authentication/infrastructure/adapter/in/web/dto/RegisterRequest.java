package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Schema(description = "Solicitud de registro de nuevo usuario")
public record RegisterRequest(
		@NotBlank @Email @Schema(example = "operador@logistics.com") String email,

		@NotBlank
		@Size(min = 8, max = 128)
		@Pattern(regexp = "^[\\S]{8,128}$", message = "La contraseña no puede contener espacios en blanco")
		@Schema(example = "Pruebas2026*") String password) {
}
