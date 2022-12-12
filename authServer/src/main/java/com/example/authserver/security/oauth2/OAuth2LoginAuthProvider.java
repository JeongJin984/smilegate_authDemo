package com.example.authserver.security.oauth2;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

public class OAuth2LoginAuthProvider implements AuthenticationProvider {
    private final RestOperations restOperations;

    public OAuth2LoginAuthProvider() {
        this.restOperations = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseConverter()));
    }

    private ResponseEntity<OAuth2AccessTokenResponse> getAccessToken(HttpEntity<?> request) {
        return this.restOperations.postForEntity("http://localhost:8080/realms/oauth2/protocol/openid-connect/token", request, OAuth2AccessTokenResponse.class);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

        params.add("grant_type", "a");
        params.add("code", "a");
        params.add("redirect_uri", "a");
        params.add("client_id", "a");
        params.add("client_secret", "a");

        HttpHeaders header = new HttpHeaders();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, header);

        OAuth2AccessTokenResponse oAuth2AuthResponse = getAccessToken(request).getBody();
        assert oAuth2AuthResponse != null;
        return new OAuth2AuthorizationCodeAuthenticationToken("a", oAuth2AuthResponse.accessToken(), oAuth2AuthResponse.refreshToken(), "a");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }

    record OAuth2AuthRequest(String code, String clientId, String clientSecret, String grantType, String redirectUrl) {}
    record OAuth2AuthResponse(String accessToken, String refreshToken) {}
}
