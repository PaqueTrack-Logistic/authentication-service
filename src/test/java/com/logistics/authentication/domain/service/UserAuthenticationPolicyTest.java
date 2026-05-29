package com.logistics.authentication.domain.service;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;

/**
 * Cubre todas las ramas de las reglas de dominio para autenticar:
 * estados de registro (PENDING/REJECTED/APPROVED), enabled y bloqueo temporal.
 */
class UserAuthenticationPolicyTest {

	private static final Instant NOW = Instant.parse("2026-05-29T00:00:00Z");

	private UserAccount.UserAccountBuilder approvedUser() {
		return UserAccount.builder()
				.id(UUID.randomUUID())
				.email("user@logistics.com")
				.passwordHash("hash")
				.roles(Set.of("ROLE_OPERATOR"))
				.enabled(true)
				.registrationStatus(RegistrationStatus.APPROVED)
				.failedLoginAttempts(0)
				.createdAt(NOW);
	}

	@Test
	void approvedEnabledUnlocked_doesNotThrow() {
		assertThatCode(() -> UserAuthenticationPolicy.assertCanAuthenticate(approvedUser().build(), NOW))
				.doesNotThrowAnyException();
	}

	@Test
	void pending_throwsPendingApproval() {
		UserAccount user = approvedUser().registrationStatus(RegistrationStatus.PENDING).build();
		assertThatThrownBy(() -> UserAuthenticationPolicy.assertCanAuthenticate(user, NOW))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_PENDING_APPROVAL");
	}

	@Test
	void rejected_throwsRegistrationRejected() {
		UserAccount user = approvedUser().registrationStatus(RegistrationStatus.REJECTED).build();
		assertThatThrownBy(() -> UserAuthenticationPolicy.assertCanAuthenticate(user, NOW))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_REGISTRATION_REJECTED");
	}

	@Test
	void disabled_throwsAccountDisabled() {
		UserAccount user = approvedUser().enabled(false).build();
		assertThatThrownBy(() -> UserAuthenticationPolicy.assertCanAuthenticate(user, NOW))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_ACCOUNT_DISABLED");
	}

	@Test
	void lockedUntilInFuture_throwsAccountLocked() {
		UserAccount user = approvedUser().lockedUntil(NOW.plusSeconds(600)).build();
		assertThatThrownBy(() -> UserAuthenticationPolicy.assertCanAuthenticate(user, NOW))
				.isInstanceOf(AuthenticationDomainException.class)
				.extracting("errorCode").isEqualTo("AUTH_ACCOUNT_LOCKED");
	}

	@Test
	void lockedUntilInPast_doesNotThrow() {
		// rama isLocked == false con lockedUntil != null
		UserAccount user = approvedUser().lockedUntil(NOW.minusSeconds(600)).build();
		assertThatCode(() -> UserAuthenticationPolicy.assertCanAuthenticate(user, NOW))
				.doesNotThrowAnyException();
	}
}
