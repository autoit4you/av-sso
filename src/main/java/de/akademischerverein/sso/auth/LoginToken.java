package de.akademischerverein.sso.auth;

import lombok.*;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.time.ZonedDateTime;
import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LoginToken {
    @Id
    @Getter @Setter
    @GeneratedValue(generator = TokenGenerator.generatorName)
    @GenericGenerator(name = TokenGenerator.generatorName, strategy = "de.akademischerverein.sso.auth.TokenGenerator")
    private String id;

    @Getter @Setter
    @Column(nullable = false)
    private ZonedDateTime expires;

    @Getter @Setter
    @Column(unique = true, nullable = false)
    private long avid;

    public LoginToken(ZonedDateTime expires, long avid) {
        this.expires = expires;
        this.avid = avid;
    }
}
