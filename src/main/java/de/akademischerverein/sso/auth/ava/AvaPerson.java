package de.akademischerverein.sso.auth;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;
import java.util.stream.Collectors;

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
        var roles = new ArrayList<String>();
        if (get("Ist_Ausgeschieden", "nein").equals("nein")) {
            // Aktivitas
            if (get("AKT_JuMi", "nein").equals("ja")) {
                roles.add("ROLE_JUMI");
            }
            if (get("AKT_VoMi", "nein").equals("ja")) {
                roles.add("ROLE_VOMI");
            }
            if (get("AV_VerkGast", "nein").equals("ja")) {
                roles.add("ROLE_VERKEHRSGAST");
            }
            if (get("AKT_Ex", "nein").equals("ja")) {
                roles.add("ROLE_EXAKTIV");
            }
            if (!roles.isEmpty()) {
                roles.add("ROLE_AKTIVITAS");
            }

            // ADAHschaft
            if (get("ADH_OrdMi", "nein").equals("ja")) {
                roles.add("ROLE_ADAH");
            }

            if (!roles.isEmpty()) {
                roles.add("ROLE_AV");
            }
        }
        roles.add("ROLE_USER");

        return roles.stream().map(SimpleGrantedAuthority::new).toList();
    }

    public String getUserId() {
        return Long.toString(avid);
    }

    public boolean isEnabled() {
        return true;
    }
}
