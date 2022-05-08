package de.akademischerverein.sso.web;

import de.akademischerverein.sso.auth.AvaPerson;
import de.akademischerverein.sso.auth.AvaService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    private final AvaService avaService;

    public LoginController(AvaService avaService) {
        this.avaService = avaService;
    }

    @GetMapping("/login")
    public String login(Model model) {
        return "login";
    }

    @PostMapping("/login")
    public String login(Model model, @RequestParam("email") String email) {
        try {
            var person = avaService.userByEmail(email);
            avaService.sendLoginToken(person);
        } catch (UsernameNotFoundException e) {
            // User not found! Don't expose this to an attacker!
            System.out.println("User not found!");
        }

        return "login";
    }

    @GetMapping("/login/token/{token}")
    public String magicLogin(@PathVariable("token") String token) {
        if (avaService.attemptLoginWithToken(token)) {
            return "redirect:/";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping
    public String index(Model model, @AuthenticationPrincipal AvaPerson auth) {
        model.addAttribute("vorname", auth.get("Vorname"));
        model.addAttribute("name", auth.get("Name"));
        return "auth";
    }
}
