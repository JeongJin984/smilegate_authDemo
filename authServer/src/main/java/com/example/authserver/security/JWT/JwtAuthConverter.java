package com.example.authserver.security.JWT;

import com.example.authserver.common.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

import static com.example.authserver.common.JwtUtils.AUTHORITIES_KEY;
import static com.example.authserver.common.JwtUtils.secretKey;

public class JwtAuthConverter implements AuthenticationConverter {
    public static final String AUTHENTICATION_SCHEME_JWT = "Bearer";

    private final Charset credentialsCharset = StandardCharsets.UTF_8;

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authDetailsSource;

    public JwtAuthConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    public JwtAuthConverter(
            AuthenticationDetailsSource<HttpServletRequest, ?> authDetailsSource) {
        this.authDetailsSource = authDetailsSource;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return null;
        }
        header = header.trim();
        if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_JWT)) {
            return null;
        }
        if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_JWT)) {
            throw new BadCredentialsException("Empty basic authentication token");
        }
        String token = header.substring(7);

        Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();

        Object authoritiesClaim = claims.get(AUTHORITIES_KEY);

        Collection<? extends GrantedAuthority> authorities = authoritiesClaim == null ? AuthorityUtils.NO_AUTHORITIES
                : AuthorityUtils.commaSeparatedStringToAuthorityList(authoritiesClaim.toString());

        JwtAuthToken result = new JwtAuthToken(claims, authorities, token);
        result.setDetails(this.authDetailsSource.buildDetails(request));
        return result;
    }
}
