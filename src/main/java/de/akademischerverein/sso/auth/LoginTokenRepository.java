package de.akademischerverein.sso.auth;

import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;

public interface LoginTokenRepository extends CrudRepository<LoginToken, String> {
    Optional<LoginToken> findByAvid(long avid);
}
