package com.example.authserver.common.jwtUtils;

import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;

public class Variables {
    public static final String accessTokenSecretKey = "accessaccessaccessaccessaccessaccessaccessaccessaccessaccessaccessaccess";
    public static final Key accessTokenKey = Keys.hmacShaKeyFor(accessTokenSecretKey.getBytes(StandardCharsets.UTF_8));

    public static final String refreshTokenSecretKey = "refreshrefreshrefreshrefreshrefreshrefreshrefreshrefreshrefreshrefresh";
    public static final Key refreshTokenKey = Keys.hmacShaKeyFor(refreshTokenSecretKey.getBytes(StandardCharsets.UTF_8));
}
