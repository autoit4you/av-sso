package de.akademischerverein.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class AvSsoApplication {

    public static void main(String[] args) {
        SpringApplication.run(AvSsoApplication.class, args);
    }
}
