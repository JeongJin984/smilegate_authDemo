package com.example.authserver.security.JWT;

import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.Assert;

import java.util.Collection;

public class JwtAuthToken extends AbstractAuthenticationToken {
    private final Object principal;

    private Object credentials;

    public JwtAuthToken(Claims claims, Collection<? extends GrantedAuthority> authorities, String token) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.principal = new User(claims.getSubject(), "", authorities);
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

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated,
                "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}
