package org.wsd.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.wsd.auth.domain.ClientEntity;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<ClientEntity, String> {
    Optional<ClientEntity> findByClientId(String clientId);
}
