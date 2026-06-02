package com.logistics.authentication.infrastructure.adapter.in.web;

import org.springframework.http.HttpStatus;

/**
 * Resuelve el HTTP status a partir del código de error de autenticación.
 */
final class AuthenticationErrorHttpStatusMapper {

	private AuthenticationErrorHttpStatusMapper() {
	}

	static HttpStatus forErrorCode(String errorCode) {
		return switch (errorCode) {
			case "AUTH_ACCOUNT_LOCKED", "AUTH_ACCOUNT_DISABLED", "AUTH_PENDING_APPROVAL",
					"AUTH_REGISTRATION_REJECTED" -> HttpStatus.FORBIDDEN;
			case "AUTH_EMAIL_ALREADY_REGISTERED" -> HttpStatus.CONFLICT;
			case "AUTH_USER_NOT_FOUND" -> HttpStatus.NOT_FOUND;
			case "AUTH_INVALID_REGISTRATION_STATE" -> HttpStatus.BAD_REQUEST;
			default -> HttpStatus.UNAUTHORIZED;
		};
	}
}
