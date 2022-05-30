package de.akademischerverein.sso.auth.ava;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.util.*;

@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AvaPerson implements Serializable {
    public static final String EMAIL_0 = "Email_0";
    public static final String EMAIL_1 = "Email_1";
    public static final String EMAIL_2 = "Email_2";

    @Getter
    private long avid;
    @Getter
    private Map<String, String> properties = new HashMap<>();

    public AvaPerson(long avid) {
        this.avid = avid;
    }

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
        return "ava:" + avid;
    }

    public boolean isEnabled() {
        return true;
    }
}
