package com.example.authserver.api;

import com.example.authserver.common.JwtUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/")
    public String helloGet() {
        return "Hello Get";
    }

    @PostMapping("/")
    public String helloPost(HttpServletResponse response) {
        return "Hello Post";
    }
}
