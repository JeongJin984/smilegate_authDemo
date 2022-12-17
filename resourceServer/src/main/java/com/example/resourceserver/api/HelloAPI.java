package com.example.resourceserver.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloAPI {
    @GetMapping("/")
    public String hello() {
        return "hello world!!";
    }
}
