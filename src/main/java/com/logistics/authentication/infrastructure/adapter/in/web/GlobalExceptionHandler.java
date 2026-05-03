package com.logistics.authentication.infrastructure.adapter.in.web;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApiErrorResponse;
import com.logistics.authentication.infrastructure.adapter.in.web.filter.TraceIdFilter;

@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(AuthenticationDomainException.class)
	public ResponseEntity<ApiErrorResponse> handleAuthDomain(AuthenticationDomainException ex) {
		HttpStatus status = switch (ex.getErrorCode()) {
			case "AUTH_ACCOUNT_LOCKED", "AUTH_ACCOUNT_DISABLED" -> HttpStatus.FORBIDDEN;
			default -> HttpStatus.UNAUTHORIZED;
		};
		return ResponseEntity
				.status(status)
				.body(new ApiErrorResponse(ex.getErrorCode(), ex.getMessage(), null, currentTraceId()));
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException ex) {
		return ResponseEntity
				.status(HttpStatus.FORBIDDEN)
				.body(new ApiErrorResponse("ACCESS_DENIED", "Permisos insuficientes para este recurso", null, currentTraceId()));
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
		var details = ex.getBindingResult().getFieldErrors().stream()
				.map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
				.toList();
		return ResponseEntity
				.status(HttpStatus.BAD_REQUEST)
				.body(new ApiErrorResponse("VALIDATION_ERROR", "Payload inválido", details, currentTraceId()));
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiErrorResponse> handleGeneric(Exception ex) {
		String traceId = currentTraceId();
		if (log.isErrorEnabled()) {
			log.error("Unhandled error traceId={}", traceId, ex);
		}
		return ResponseEntity
				.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(new ApiErrorResponse(
						"INTERNAL_ERROR",
						"Error interno",
						null,
						traceId));
	}

	private static String currentTraceId() {
		return MDC.get(TraceIdFilter.TRACE_ID_MDC);
	}
}
