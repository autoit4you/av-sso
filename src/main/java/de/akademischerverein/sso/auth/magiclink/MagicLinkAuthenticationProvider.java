package de.akademischerverein.sso.auth;

import de.akademischerverein.sso.ava.AvaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;

@Component
public class SsoAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private LoginTokenRepository loginTokenRepository;
    @Autowired
    private AvaService avaService;

    public Authentication authenticatePasswordless(PasswordlessAuthenticationToken authenticationToken) throws AuthenticationException {
        var usedToken = loginTokenRepository.findById((String) authenticationToken.getCredentials());

        if (usedToken.isEmpty()) {
            throw new BadCredentialsException("Invalid token");
        }

        loginTokenRepository.delete(usedToken.get());

        if (usedToken.get().getExpires().isBefore(ZonedDateTime.now())) {
            throw new BadCredentialsException("Invalid token");
        }

        var person = avaService.findById(usedToken.get().getAvid());

        if (person.isEmpty()) {
            throw new UsernameNotFoundException("invalid avid?");
        }
        if (!person.get().isEnabled()) {
            throw new DisabledException("account is disabled");
        }
        return new PasswordlessAuthenticationToken(person.get().getUserId(), authenticationToken.getCredentials(), person.get().getAuthorities());
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof PasswordlessAuthenticationToken) {
            return authenticatePasswordless((PasswordlessAuthenticationToken) authentication);
        }

        throw new AuthenticationServiceException("Unsupported authentication");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordlessAuthenticationToken.class.equals(authentication);
    }
}
