package com.logistics.authentication.infrastructure.adapter.out.persistence.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.logistics.authentication.infrastructure.adapter.out.persistence.entity.RoleEntity;

public interface RoleJpaRepository extends JpaRepository<RoleEntity, UUID> {

	Optional<RoleEntity> findByName(String name);
}
