package com.logistics.authentication.application.port.out;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;

public interface UserRepositoryPort {

	Optional<UserAccount> findByEmail(String email);

	Optional<UserAccount> findById(UUID id);

	boolean existsByEmail(String email);

	void savePendingUser(UUID id, String email, String passwordHash, UUID operatorRoleId);

	List<UserAccount> findByRegistrationStatus(RegistrationStatus status);

	void updateRegistrationStatus(UUID userId, RegistrationStatus status, boolean enabled);

	void approvePendingUser(UUID userId, UUID roleId);

	void resetFailedLogin(UUID userId);

	void registerFailedLogin(UUID userId, int newAttemptCount, java.time.Instant lockedUntilOrNull);
}
