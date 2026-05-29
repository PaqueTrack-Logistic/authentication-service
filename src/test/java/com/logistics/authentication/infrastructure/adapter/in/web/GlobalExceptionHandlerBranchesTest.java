package com.logistics.authentication.infrastructure.adapter.in.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;

import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApiErrorResponse;

/**
 * Cubre todos los arms del switch de mapeo excepción->HTTP y los handlers de
 * acceso denegado y error genérico.
 */
class GlobalExceptionHandlerBranchesTest {

	private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

	private int statusOf(String errorCode) {
		ResponseEntity<ApiErrorResponse> r =
				handler.handleAuthDomain(new AuthenticationDomainException(errorCode, "msg"));
		return r.getStatusCode().value();
	}

	@Test
	void pendingApproval_maps403() {
		assertThat(statusOf("AUTH_PENDING_APPROVAL")).isEqualTo(403);
	}

	@Test
	void emailAlreadyRegistered_maps409() {
		assertThat(statusOf("AUTH_EMAIL_ALREADY_REGISTERED")).isEqualTo(409);
	}

	@Test
	void userNotFound_maps404() {
		assertThat(statusOf("AUTH_USER_NOT_FOUND")).isEqualTo(404);
	}

	@Test
	void invalidRegistrationState_maps400() {
		assertThat(statusOf("AUTH_INVALID_REGISTRATION_STATE")).isEqualTo(400);
	}

	@Test
	void unknownCode_mapsTo401ByDefault() {
		assertThat(statusOf("AUTH_INVALID_CREDENTIALS")).isEqualTo(401);
	}

	@Test
	void accessDenied_maps403() {
		ResponseEntity<ApiErrorResponse> r = handler.handleAccessDenied(new AccessDeniedException("denied"));
		assertThat(r.getStatusCode().value()).isEqualTo(403);
		assertThat(r.getBody().errorCode()).isEqualTo("ACCESS_DENIED");
	}

	@Test
	void genericException_maps500() {
		ResponseEntity<ApiErrorResponse> r = handler.handleGeneric(new RuntimeException("boom"));
		assertThat(r.getStatusCode().value()).isEqualTo(500);
		assertThat(r.getBody().errorCode()).isEqualTo("INTERNAL_ERROR");
	}
}
