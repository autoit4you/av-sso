package de.akademischerverein.sso.auth;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

@RequiredArgsConstructor
@ToString
public class AvaPerson {
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

    void setProperty(String prop, String newVal) {
        properties.put(prop, newVal);
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Set.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    public String getUserId() {
        return Long.toString(avid);
    }

    public boolean isEnabled() {
        return true;
    }
}
