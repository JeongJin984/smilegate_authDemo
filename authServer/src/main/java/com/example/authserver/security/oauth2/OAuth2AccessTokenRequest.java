package com.example.authserver.security.oauth2;

public record OAuth2AccessTokenRequest(
        String grantType,
        String code,
        String redirectUri,
        String clientId,
        String clientSecret
) {
}


