package org.wsd.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthenticationController {
    @GetMapping("/auth/signIn")
    public String signIn() {
        return "signIn";
    }
}
