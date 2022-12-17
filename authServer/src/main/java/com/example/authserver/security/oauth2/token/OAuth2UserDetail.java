package com.example.authserver.security.oauth2.token;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class OAuth2UserDetail implements UserDetails {
    private String accessToken;
    private String expiresIn;
    private String refreshToken;
    private String tokenType;
    private String scope;

    public OAuth2UserDetail(String accessToken, String expiresIn, String refreshToken, String tokenType, String scope) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        this.scope = scope;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return this.refreshToken;
    }

    @Override
    public String getUsername() {
        return this.accessToken;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
