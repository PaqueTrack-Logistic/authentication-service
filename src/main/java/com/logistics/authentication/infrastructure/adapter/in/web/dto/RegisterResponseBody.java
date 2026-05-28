package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Registro recibido; pendiente de aprobación admin")
public record RegisterResponseBody(
		UUID userId,
		String email,
		String status,
		String message) {
}
