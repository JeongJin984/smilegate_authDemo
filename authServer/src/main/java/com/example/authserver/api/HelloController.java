package com.example.authserver.api;

import org.springframework.web.bind.annotation.GetMapping;

public class HelloController {

    @GetMapping("/")
    public String hello() {
        return "Hello";
    }
}
