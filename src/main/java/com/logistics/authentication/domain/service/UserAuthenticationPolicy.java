package com.logistics.authentication.domain.service;

import java.time.Instant;

import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;

/**
 * Reglas de dominio para permitir login / refresh.
 */
public final class UserAuthenticationPolicy {

	private UserAuthenticationPolicy() {
	}

	public static void assertCanAuthenticate(UserAccount user, Instant now) {
		if (user.getRegistrationStatus() == RegistrationStatus.PENDING) {
			throw new AuthenticationDomainException(
					"AUTH_PENDING_APPROVAL",
					"Tu cuenta está pendiente de aprobación por un administrador");
		}
		if (user.getRegistrationStatus() == RegistrationStatus.REJECTED) {
			throw new AuthenticationDomainException(
					"AUTH_REGISTRATION_REJECTED",
					"Tu solicitud de registro fue rechazada");
		}
		if (!user.isEnabled()) {
			throw new AuthenticationDomainException("AUTH_ACCOUNT_DISABLED", "Cuenta deshabilitada");
		}
		if (user.isLocked(now)) {
			throw new AuthenticationDomainException("AUTH_ACCOUNT_LOCKED", "Cuenta bloqueada temporalmente");
		}
	}
}
