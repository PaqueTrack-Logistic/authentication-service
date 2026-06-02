package com.logistics.authentication.domain.service;

/**
 * Mapea códigos de error de dominio a motivos de auditoría de login.
 */
public final class LoginAuditReasonMapper {

	private LoginAuditReasonMapper() {
	}

	public static String forAuthError(String errorCode) {
		return switch (errorCode) {
			case "AUTH_PENDING_APPROVAL" -> "PENDING_APPROVAL";
			case "AUTH_REGISTRATION_REJECTED" -> "REGISTRATION_REJECTED";
			case "AUTH_ACCOUNT_DISABLED" -> "USER_DISABLED";
			case "AUTH_ACCOUNT_LOCKED" -> "ACCOUNT_LOCKED";
			default -> "AUTH_BLOCKED";
		};
	}
}
