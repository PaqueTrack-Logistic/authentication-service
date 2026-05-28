package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Usuarios con registro pendiente de aprobación")
public record PendingUserResponseBody(List<PendingUserItem> users) {

	@Schema(description = "Solicitud pendiente")
	public record PendingUserItem(UUID id, String email, Instant createdAt, java.util.List<String> roles) {
	}
}
