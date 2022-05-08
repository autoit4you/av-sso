package de.akademischerverein.sso.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.*;

import static de.akademischerverein.sso.auth.AvaPerson.*;

@Service
@Slf4j
public class AvaService {
    private final HashMap<Long, AvaPerson> persons = new HashMap<>();
    @Value("${ava.username}")
    private String ava_username;
    @Value("${ava.password}")
    private String ava_password;
    @Value("${ava.fix_file}")
    private String ava_fix;
    @Value("${ava.changes_file}")
    private String ava_changes;
    @Value("${ava.encryption_key}")
    private String ava_key;

    private final LoginTokenRepository loginTokenRepository;

    public AvaService(LoginTokenRepository loginTokenRepository) {
        this.loginTokenRepository = loginTokenRepository;
    }

    public void loadPersons() {
        var client = HttpClient.newBuilder()
                .authenticator(new Authenticator(){
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(ava_username, ava_password.toCharArray());
                    }
                }).build();
        loadAvaFile(client, ava_fix);
        loadAvaFile(client, ava_changes);

        log.info("Loaded {} persons/accounts!", persons.size());
    }

    private void loadAvaFile(HttpClient client, String url) {
        var avidFilter = Set.of(132890L, 121541L, 129883L, 127749L, 136964L, 138516L, 106409L, 119019L, 114945L);
        var request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();

        try {
            var resp = client.send(request, HttpResponse.BodyHandlers.ofString());

            for(var line : resp.body().lines().toList()) {
                var bytes = HexFormat.of().parseHex(line);
                var iv = Arrays.copyOf(bytes, 8);
                var encryptedLine = Arrays.copyOfRange(bytes, 8, bytes.length);
                var cipher = Cipher.getInstance("Blowfish/CBC/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(ava_key.getBytes(), "Blowfish"), new IvParameterSpec(iv));
                var decoding = new String(cipher.doFinal(encryptedLine), "latin1");
                decoding = decoding.substring(0, decoding.indexOf(0));

                if (!decoding.endsWith("<AV1872>")) {
                    throw new RuntimeException("Line guard missing");
                }

                decoding = decoding.substring(0, decoding.length() - 8);
                var parsed_line = decoding.split("\\|");
                if (parsed_line[4].equals("SetAttrib")) {
                    var avId = Long.parseLong(parsed_line[5]);
                    var attrib = parsed_line[6];
                    var newValue = parsed_line[7];

                    if (!avidFilter.contains(avId)) {
                        continue;
                    }

                    var p = persons.getOrDefault(avId, new AvaPerson(avId));
                    p.setProperty(attrib, newValue);

                    if (!persons.containsKey(avId)) {
                        persons.put(avId, p);
                    }
                }
            }

        } catch (IOException | InterruptedException | NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public AvaPerson userByEmail(String email) throws UsernameNotFoundException {
        for (var person : persons.values()) {
            if (person.get(EMAIL_0, "").equalsIgnoreCase(email)) {
                return person;
            } else if (person.get(EMAIL_1, "").equalsIgnoreCase(email)) {
                return person;
            } else if (person.get(EMAIL_2, "").equalsIgnoreCase(email)) {
                return person;
            }
        }

        throw new UsernameNotFoundException("email not found");
    }

    public void sendLoginToken(AvaPerson person) {
        var currentToken = loginTokenRepository.findByAvid(person.getAvid());
        if (currentToken.isPresent()) {
            if (currentToken.get().getExpires().isAfter(ZonedDateTime.now())) {
                return;
            } else {
                loginTokenRepository.delete(currentToken.get());
            }
        }

        var token = new LoginToken(ZonedDateTime.now().plusMinutes(5), person.getAvid());
        loginTokenRepository.save(token);

        log.info("Generated token {}", token.getId());
    }

    public boolean attemptLoginWithToken(String token) {
        var usedToken = loginTokenRepository.findById(token);

        if (usedToken.isEmpty()) {
            return false;
        }

        loginTokenRepository.delete(usedToken.get());

        if (usedToken.get().getExpires().isBefore(ZonedDateTime.now())) {
            return false;
        }

        var person = persons.get(usedToken.get().getAvid());

        var sc = SecurityContextHolder.getContext();
        sc.setAuthentication(new UsernamePasswordAuthenticationToken(person, null, List.of(new SimpleGrantedAuthority("ROLE_USER"))));
        return true;
    }
}
