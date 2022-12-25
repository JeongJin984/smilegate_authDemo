package com.example.authserver.security.oauth2.token;

import com.example.authserver.security.AbstractAuthFilter;
import io.jsonwebtoken.gson.io.GsonDeserializer;
import io.jsonwebtoken.io.Decoders;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

public class OAuth2TokenFilter extends AbstractAuthFilter {
    public OAuth2TokenFilter(AuthenticationEntryPoint entryPoint) {
        super(new OAuth2TokenConverter(), new AntPathRequestMatcher("/login/oauth2/code/keycloack"), entryPoint);
    }

    @Override
    protected void setCookieWithTokenInfo(HttpServletResponse response, Authentication authResult) throws IOException {
        OAuth2AuthToken token = (OAuth2AuthToken) authResult;
        Cookie platformCookie = new Cookie("platform", "keycloack");
        platformCookie.setPath("/");
        platformCookie.setSecure(false);
        platformCookie.setHttpOnly(false);

        Cookie accessCookie = new Cookie("accessToken", token.getAccessToken());
        accessCookie.setPath("/");
        accessCookie.setSecure(false);
        accessCookie.setHttpOnly(true);

        Cookie refreshCookie = new Cookie("refreshToken", token.getRefreshToken());
        refreshCookie.setPath("/");
        refreshCookie.setSecure(false);
        refreshCookie.setHttpOnly(true);

        Cookie oidcCookie = new Cookie("idToken", token.getIdToken());
        oidcCookie.setPath("/");
        oidcCookie.setSecure(false);
        oidcCookie.setHttpOnly(true);

        Map<String, ?> decode = new GsonDeserializer<Map<String, ?>>()
                .deserialize(Decoders.BASE64.decode(token.getIdToken().split("\\.")[1]));
        Cookie loginUser = new Cookie("user", decode.get("jti").toString());
        loginUser.setPath("/");
        loginUser.setSecure(false);
        loginUser.setHttpOnly(true);

        double d = Double.parseDouble(decode.get("exp").toString());
        Cookie expireAt = new Cookie("expireAt", Instant.ofEpochSecond((int)d).toString());
        expireAt.setPath("/");
        expireAt.setSecure(false);
        expireAt.setHttpOnly(true);

        response.addCookie(platformCookie);
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
        response.addCookie(oidcCookie);
        response.addCookie(loginUser);
        response.addCookie(expireAt);

        response.sendRedirect("http://localhost:3000");
    }

    @Override
    protected Authentication authenticate(HttpServletRequest request, HttpServletResponse response, Authentication unAuthenticated) {
        unAuthenticated.setAuthenticated(true);
        return unAuthenticated;
    }
}
