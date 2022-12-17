package com.example.resourceserver.security.JWT;

import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class JwtAuthToken extends AbstractAuthenticationToken {
    private final Object principal;

    private Object credentials;

    public JwtAuthToken(String username, Collection<? extends GrantedAuthority> authorities, String token) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.principal = new User(username, "", authorities);
        this.credentials = token;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public void setCredentials(Object credentials) {
        this.credentials = credentials;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}
