package com.logistics.authentication.application.service;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.logistics.authentication.application.port.in.ManageUserRegistrationUseCase;
import com.logistics.authentication.application.port.out.RoleRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;
import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ManageUserRegistrationService implements ManageUserRegistrationUseCase {

	private static final Set<String> ASSIGNABLE_ROLES = Set.of("ROLE_OPERATOR", "ROLE_ADMIN");

	private final UserRepositoryPort users;
	private final RoleRepositoryPort roles;

	@Override
	@Transactional(readOnly = true)
	public List<String> listAssignableRoles() {
		return ASSIGNABLE_ROLES.stream().sorted().toList();
	}

	@Override
	@Transactional(readOnly = true)
	public List<PendingUser> listPending() {
		return users.findByRegistrationStatus(RegistrationStatus.PENDING).stream()
				.map(u -> new PendingUser(
						u.getId(),
						u.getEmail(),
						u.getCreatedAt(),
						u.getRoles() == null ? List.of() : List.copyOf(u.getRoles())))
				.toList();
	}

	@Override
	@Transactional
	public void approve(UUID userId, String roleName) {
		requirePending(userId);
		String role = roleName == null ? "" : roleName.trim();
		if (!ASSIGNABLE_ROLES.contains(role)) {
			throw new AuthenticationDomainException(
					"AUTH_INVALID_ROLE",
					"Rol no permitido. Use ROLE_OPERATOR o ROLE_ADMIN");
		}
		UUID roleId = roles.findRoleIdByName(role)
				.orElseThrow(() -> new IllegalStateException("Rol no configurado en BD: " + role));
		users.approvePendingUser(userId, roleId);
	}

	@Override
	@Transactional
	public void reject(UUID userId) {
		UserAccount user = requirePending(userId);
		users.updateRegistrationStatus(user.getId(), RegistrationStatus.REJECTED, false);
	}

	private UserAccount requirePending(UUID userId) {
		UserAccount user = users.findById(userId)
				.orElseThrow(() -> new AuthenticationDomainException(
						"AUTH_USER_NOT_FOUND",
						"Usuario no encontrado"));
		if (user.getRegistrationStatus() != RegistrationStatus.PENDING) {
			throw new AuthenticationDomainException(
					"AUTH_INVALID_REGISTRATION_STATE",
					"La solicitud no está pendiente de aprobación");
		}
		return user;
	}
}
