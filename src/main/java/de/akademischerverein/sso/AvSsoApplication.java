package de.akademischerverein.sso;

import de.akademischerverein.sso.auth.AvaService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AvSsoApplication {

    public static void main(String[] args) {
        SpringApplication.run(AvSsoApplication.class, args);
    }

    @Bean
    public CommandLineRunner cmdRunner(AvaService loader) {
        return (args) -> {
              loader.loadPersons();
        };
    }
}
