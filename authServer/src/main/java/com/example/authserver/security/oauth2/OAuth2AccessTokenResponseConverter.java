package com.example.authserver.security.oauth2;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;

import java.io.IOException;

public class OAuth2AccessTokenResponseConverter extends AbstractHttpMessageConverter<OAuth2AccessTokenResponse> {
    @Override
    protected boolean supports(Class<?> clazz) {
        return false;
    }

    @Override
    protected OAuth2AccessTokenResponse readInternal(Class<? extends OAuth2AccessTokenResponse> clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
        return null;
    }

    @Override
    protected void writeInternal(OAuth2AccessTokenResponse oAuth2AccessTokenResponse, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {

    }
}
