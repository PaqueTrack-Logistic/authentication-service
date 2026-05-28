package com.logistics.authentication.application.port.in;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface ManageUserRegistrationUseCase {

	List<String> listAssignableRoles();

	List<PendingUser> listPending();

	void approve(UUID userId, String roleName);

	void reject(UUID userId);

	record PendingUser(UUID id, String email, Instant createdAt, List<String> roles) {
	}
}
