package de.akademischerverein.sso.auth.magiclink;

import de.akademischerverein.sso.auth.magiclink.LoginToken;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface LoginTokenRepository extends CrudRepository<LoginToken, String> {
    Optional<LoginToken> findByAvid(long avid);
}
