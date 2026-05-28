package com.logistics.authentication.domain.model;

/**
 * Ciclo de vida del registro: solicitud → revisión admin → acceso o rechazo.
 */
public enum RegistrationStatus {
	PENDING,
	APPROVED,
	REJECTED
}
