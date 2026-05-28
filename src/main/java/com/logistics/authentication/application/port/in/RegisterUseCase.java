package com.logistics.authentication.application.port.in;

import java.util.UUID;

public interface RegisterUseCase {

	RegisterResult register(RegisterCommand command);

	record RegisterCommand(String email, String rawPassword) {
	}

	record RegisterResult(UUID userId, String email, String status, String message) {
	}
}
