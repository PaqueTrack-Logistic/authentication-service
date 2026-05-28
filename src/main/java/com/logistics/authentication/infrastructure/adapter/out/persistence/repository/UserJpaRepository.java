package com.logistics.authentication.infrastructure.adapter.out.persistence.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.UserEntity;

public interface UserJpaRepository extends JpaRepository<UserEntity, UUID> {

	boolean existsByEmailIgnoreCase(String email);

	Optional<UserEntity> findByEmailIgnoreCase(String email);

	List<UserEntity> findByRegistrationStatusOrderByCreatedAtAsc(String registrationStatus);

	/**
	 * Consulta no trivial: join usuario-roles, agregación y agrupación (reporte operativo).
	 */
	@Query("select r.name, count(distinct u.id) from UserEntity u join u.roles r group by r.name order by r.name")
	List<Object[]> countUsersGroupedByRole();

	@Modifying
	@Query("update UserEntity u set u.failedLoginAttempts = 0, u.lockedUntil = null where u.id = :id")
	void resetFailedLogin(@Param("id") UUID id);

	@Modifying
	@Query("update UserEntity u set u.failedLoginAttempts = :attempts, u.lockedUntil = :lockedUntil where u.id = :id")
	void updateFailedLogin(
			@Param("id") UUID id,
			@Param("attempts") int attempts,
			@Param("lockedUntil") java.time.Instant lockedUntil);

	@Modifying
	@Query("update UserEntity u set u.registrationStatus = :status, u.enabled = :enabled, u.updatedAt = CURRENT_TIMESTAMP where u.id = :id")
	void updateRegistrationStatus(
			@Param("id") UUID id,
			@Param("status") String status,
			@Param("enabled") boolean enabled);
}
