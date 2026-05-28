package com.logistics.authentication.infrastructure.adapter.out.persistence.mapper;

import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.logistics.authentication.domain.model.RegistrationStatus;
import com.logistics.authentication.domain.model.UserAccount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.UserEntity;

@Component
public class UserMapper {

	public UserAccount toDomain(UserEntity entity) {
		var roles = entity.getRoles().stream()
				.map(r -> r.getName())
				.collect(Collectors.toUnmodifiableSet());
		return UserAccount.builder()
				.id(entity.getId())
				.email(entity.getEmail())
				.passwordHash(entity.getPasswordHash())
				.roles(roles)
				.enabled(entity.isEnabled())
				.registrationStatus(parseStatus(entity.getRegistrationStatus()))
				.failedLoginAttempts(entity.getFailedLoginAttempts())
				.lockedUntil(entity.getLockedUntil())
				.createdAt(entity.getCreatedAt())
				.build();
	}

	private static RegistrationStatus parseStatus(String value) {
		if (value == null || value.isBlank()) {
			return RegistrationStatus.APPROVED;
		}
		return RegistrationStatus.valueOf(value);
	}
}
