package com.logistics.authentication.application.service;

import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.logistics.authentication.application.port.in.RegisterUseCase;
import com.logistics.authentication.application.port.out.PasswordEncoderPort;
import com.logistics.authentication.application.port.out.RoleRepositoryPort;
import com.logistics.authentication.application.port.out.UserRepositoryPort;
import com.logistics.authentication.domain.exception.AuthenticationDomainException;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RegisterService implements RegisterUseCase {

	private static final String DEFAULT_ROLE = "ROLE_OPERATOR";

	private final UserRepositoryPort users;
	private final RoleRepositoryPort roles;
	private final PasswordEncoderPort passwordEncoder;

	@Override
	@Transactional
	public RegisterResult register(RegisterCommand command) {
		String email = command.email().trim().toLowerCase();
		if (users.existsByEmail(email)) {
			throw new AuthenticationDomainException(
					"AUTH_EMAIL_ALREADY_REGISTERED",
					"No se pudo completar el registro con ese correo");
		}
		UUID roleId = roles.findRoleIdByName(DEFAULT_ROLE)
				.orElseThrow(() -> new IllegalStateException("Rol " + DEFAULT_ROLE + " no configurado en BD"));
		UUID userId = UUID.randomUUID();
		String hash = passwordEncoder.encode(command.rawPassword());
		users.savePendingUser(userId, email, hash, roleId);
		return new RegisterResult(
				userId,
				email,
				"PENDING",
				"Solicitud registrada. Un administrador debe aprobar tu cuenta antes de iniciar sesión.");
	}
}
