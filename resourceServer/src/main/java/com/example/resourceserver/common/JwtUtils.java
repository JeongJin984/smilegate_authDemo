package com.example.resourceserver.common;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtUtils {
    public static final String AUTHORITIES_KEY = "permissions";

    public static final String accessTokenSecret = "accesssaccesssaccesssaccesssaccesssaccesss";
    public static final SecretKey secretKey = Keys.hmacShaKeyFor(accessTokenSecret.getBytes(StandardCharsets.UTF_8));


    public static final String refreshTokenSecret = "refreshrefreshrefreshrefreshrefreshrefreshrefreshrefreshrefresh";
    public static final SecretKey refreshSecretKey = Keys.hmacShaKeyFor(refreshTokenSecret.getBytes(StandardCharsets.UTF_8));

}
