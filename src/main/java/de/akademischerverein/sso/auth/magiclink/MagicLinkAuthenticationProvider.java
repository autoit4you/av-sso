package de.akademischerverein.sso.auth.magiclink;

import de.akademischerverein.sso.auth.magiclink.LoginTokenRepository;
import de.akademischerverein.sso.auth.magiclink.MagicLinkAuthenticationToken;
import de.akademischerverein.sso.ava.AvaPerson;
import de.akademischerverein.sso.ava.AvaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Optional;

@Component
public class MagicLinkAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private LoginTokenRepository loginTokenRepository;
    @Autowired
    private AvaService avaService;

    public Authentication authenticatePasswordless(MagicLinkAuthenticationToken authenticationToken) throws AuthenticationException {
        var usedToken = loginTokenRepository.findById((String) authenticationToken.getCredentials());

        if (usedToken.isEmpty()) {
            throw new BadCredentialsException("Invalid token");
        }

        loginTokenRepository.delete(usedToken.get());

        if (usedToken.get().getExpires().isBefore(ZonedDateTime.now())) {
            throw new BadCredentialsException("Invalid token");
        }

        var userId = usedToken.get().getUserId().split(":");
        Optional<AvaPerson> person;
        if (userId[0].equals("ava")) {
            person = avaService.findById(Long.parseLong(userId[1]));
            if (person.isEmpty()) {
                throw new UsernameNotFoundException("invalid avid?");
            }
        } else {
            throw new UsernameNotFoundException("invalid user id");
        }

        if (!person.get().isEnabled()) {
            throw new DisabledException("account is disabled");
        }
        return new MagicLinkAuthenticationToken(person.get().getUserId(), authenticationToken.getCredentials(), person.get().getAuthorities());
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof MagicLinkAuthenticationToken) {
            return authenticatePasswordless((MagicLinkAuthenticationToken) authentication);
        }

        throw new AuthenticationServiceException("Unsupported authentication");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MagicLinkAuthenticationToken.class.equals(authentication);
    }
}
