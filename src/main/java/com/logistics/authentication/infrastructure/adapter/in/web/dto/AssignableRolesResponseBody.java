package com.logistics.authentication.infrastructure.adapter.in.web.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Roles que un administrador puede asignar al aprobar un registro")
public record AssignableRolesResponseBody(List<String> roles) {
}
