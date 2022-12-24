package com.example.resourceserver.security.JWT;

import com.example.resourceserver.common.DefaultJwtParser;
import com.example.resourceserver.common.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.*;

import static com.example.resourceserver.common.JwtUtils.AUTHORITIES_KEY;
import static com.example.resourceserver.common.JwtUtils.secretKey;

public class JwtAuthConverter implements AuthenticationConverter {

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authDetailsSource;
    private final RestTemplate restTemplate = new RestTemplate();

    public JwtAuthConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    public JwtAuthConverter(
            AuthenticationDetailsSource<HttpServletRequest, ?> authDetailsSource) {
        this.authDetailsSource = authDetailsSource;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null || cookies.length == 0) {
            return null;
        }

        String accessToken = "";
        String refreshToken = "";
        Instant expireAt = null;
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals("accessToken")) {
                accessToken = cookie.getValue();
            } else if(cookie.getName().equals("refreshToken")) {
                refreshToken = cookie.getValue();
            } else if(cookie.getName().equals("expireAt")) {
                expireAt = Instant.parse(cookie.getValue());
            }
        }

        assert expireAt != null;
        assert StringUtils.hasText(accessToken);
        assert StringUtils.hasText(refreshToken);

        if(StringUtils.hasText(accessToken)) {
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.add(HttpHeaders.AUTHORIZATION,  accessToken);
                headers.add(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, refreshToken);

                if(expireAt.isAfter(Instant.now())) {
                    accessToken = (String) Objects.requireNonNull(restTemplate
                                    .exchange("http://localhost:8081/jwt/refresh/", HttpMethod.GET, new HttpEntity<String>(headers), HashMap.class)
                                    .getBody())
                            .get("accessToken");
                }
                Map<String, ?> body = new DefaultJwtParser()
                        .getBody(accessToken);
                return new JwtAuthToken((String) body.get("aud"), List.of(), accessToken);
            } catch (RestClientException exception) {
                throw new RestClientException(exception.getLocalizedMessage());
            }
        } else {
            return null;
        }
    }
}
