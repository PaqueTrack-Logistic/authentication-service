package com.logistics.authentication.application.port.out;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepositoryPort {

	Optional<UUID> findRoleIdByName(String roleName);
}
