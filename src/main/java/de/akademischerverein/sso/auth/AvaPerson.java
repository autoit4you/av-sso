package de.akademischerverein.sso.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

@RequiredArgsConstructor
@ToString
public class AvaPerson implements UserDetails {
    public static final String EMAIL_0 = "Email_0";
    public static final String EMAIL_1 = "Email_1";
    public static final String EMAIL_2 = "Email_2";

    @Getter
    private final long avid;
    @Getter
    private final Map<String, String> properties = new HashMap<>();

    public String get(String prop, String defaultValue) {
        return properties.getOrDefault(prop, defaultValue);
    }

    public String get(String prop) {
        return get(prop, null);
    }

    public Collection<String> emails() {
        var emails = new HashSet<String>();

        if (get(EMAIL_0, "").length() > 0) {
            emails.add(get(EMAIL_0));
        }
        if (get(EMAIL_1, "").length() > 0) {
            emails.add(get(EMAIL_1));
        }
        if (get(EMAIL_2, "").length() > 0) {
            emails.add(get(EMAIL_2));
        }
        return emails;
    }

    void setProperty(String prop, String newVal) {
        properties.put(prop, newVal);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Set.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return "{noop}123456";
    }

    @Override
    public String getUsername() {
        return Long.toString(avid);
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
