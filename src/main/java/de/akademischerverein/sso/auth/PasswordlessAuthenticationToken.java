package de.akademischerverein.sso.auth;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@ToString
public class PasswordlessAuthenticationToken implements Authentication, CredentialsContainer {
    private Object principal;
    private Collection<? extends GrantedAuthority> authorities;
    @Getter
    private boolean authenticated = false;
    private Object token;

    public PasswordlessAuthenticationToken(Object token) {
        this.token = token;
        this.principal = null;
        authorities = AuthorityUtils.NO_AUTHORITIES;
    }

    public PasswordlessAuthenticationToken(Object principal, Object token, Collection<? extends GrantedAuthority> authorities) {
        this.token = token;

        if (authorities != null) {
            this.authorities = Collections.unmodifiableList(new ArrayList<>(authorities));
        }
        this.principal = principal;
        authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to be authenticated");
        }
    }

    @Override
    public String getName() {
        return principal == null ? "" : principal.toString();
    }

    @Override
    public void eraseCredentials() {
        token = null;
    }
}
