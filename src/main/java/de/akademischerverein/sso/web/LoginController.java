package de.akademischerverein.sso.web;

import de.akademischerverein.sso.auth.magiclink.MagicLinkAuthenticationToken;
import de.akademischerverein.sso.ava.AvaService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
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
    private final AuthenticationManager authenticationManager;

    public LoginController(AvaService avaService, AuthenticationManager authenticationManager) {
        this.avaService = avaService;
        this.authenticationManager = authenticationManager;
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
        var magicToken = new PasswordlessAuthenticationToken(token);
        var auth = authenticationManager.authenticate(magicToken);

        if (auth.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(auth);
            return "redirect:/";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping
    public String index(Model model, @AuthenticationPrincipal AvaPerson auth) {
        System.out.println(auth);
        System.out.println(SecurityContextHolder.getContext().getAuthentication());
        model.addAttribute("vorname", auth.get("Vorname"));
        model.addAttribute("name", auth.get("Name"));
        model.addAttribute("roles", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        return "auth";
    }
}
