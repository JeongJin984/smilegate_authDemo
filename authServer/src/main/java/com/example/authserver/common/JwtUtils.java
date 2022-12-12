package com.example.authserver.common;

import io.jsonwebtoken.*;
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

    public static final String accessTokenSecret = "secretsecretsecretsecretsecretsecret";
    public static final String accessTokenExpirationTime = "99";
    public static final SecretKey secretKey = Keys.hmacShaKeyFor(accessTokenSecret.getBytes(StandardCharsets.UTF_8));


    public static final String refreshTokenExpirationTime = "9999";
    public static final String refreshTokenSecret = "refreshrefreshrefreshrefreshrefreshrefresh";
    public static final SecretKey refreshSecretKey = Keys.hmacShaKeyFor(refreshTokenSecret.getBytes(StandardCharsets.UTF_8));

    public static String createAccessToken(Authentication authentication) {
        String username = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Claims claims = Jwts.claims().setSubject(username);
        if (authorities != null) {
            claims.put(AUTHORITIES_KEY
                    , authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")));
        }

        final Date createdDate = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(new Date(createdDate.getTime() + Long.parseLong(accessTokenExpirationTime)))
                .signWith(secretKey)
                .compact();
    }

    public static boolean isNonExpiredAccessToken(String token) {
        try {
            Jws<Claims> claims = Jwts
                    .parserBuilder().setSigningKey(secretKey).build()
                    .parseClaimsJws(token);

            return claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtException(e.getMessage());
        }
    }


    public static String createRefreshToken(String username) {
        Claims claims = Jwts.claims().setSubject(username);

        final Date createdDate = new Date();
        final Date expirationDate = new Date(createdDate.getTime() + Long.parseLong(refreshTokenExpirationTime));
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(refreshSecretKey)
                .compact();
    }

    public static boolean isNonExpiredRefreshToken(String token) {
        try {
            Jws<Claims> claims = Jwts
                    .parserBuilder().setSigningKey(refreshSecretKey).build()
                    .parseClaimsJws(token);

            return claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtException(e.getMessage());
        }
    }
}
