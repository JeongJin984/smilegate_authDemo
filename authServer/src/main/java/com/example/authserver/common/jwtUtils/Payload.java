package com.example.authserver.common.jwtUtils;

import lombok.Getter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Getter
public class Payload {
    private Map<String, String> registeredClaims = new HashMap<>();
    private Map<String, String> publicClaims = new HashMap<>();
    private Map<String, String> privateClaims = new HashMap<>();
}
