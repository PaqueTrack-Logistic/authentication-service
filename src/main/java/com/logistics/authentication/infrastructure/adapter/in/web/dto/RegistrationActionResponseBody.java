package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Resultado de aprobar o rechazar registro")
public record RegistrationActionResponseBody(UUID userId, String status, String message) {
}
