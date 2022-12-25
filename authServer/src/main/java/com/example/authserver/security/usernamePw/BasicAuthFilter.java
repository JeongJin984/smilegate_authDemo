package com.example.authserver.security.usernamePw;

import com.example.authserver.common.DefaultJwtBuilder;
import com.example.authserver.security.AbstractAuthFilter;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;

import static com.example.authserver.common.jwtUtils.Variables.accessTokenKey;
import static com.example.authserver.common.jwtUtils.Variables.refreshTokenKey;

public class BasicAuthFilter extends AbstractAuthFilter {
    private final AuthenticationManager authenticationManager;

    public BasicAuthFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint entryPoint) {
        super(new BasicAuthConverter(), new AntPathRequestMatcher("/login/jwt/*"), entryPoint);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected Authentication authenticate(HttpServletRequest request, HttpServletResponse response, Authentication unAuthenticated) {
        UsernamePasswordAuthenticationToken authenticated = (UsernamePasswordAuthenticationToken)unAuthenticated;
        return authenticationManager.authenticate(authenticated);
    }

    @Override
    protected void setCookieWithTokenInfo(
            HttpServletResponse response,
            Authentication authResult
    ) throws IOException {
        Cookie loginPlatform = new Cookie("platform", "JWT");
        loginPlatform.setPath("/");
        loginPlatform.setSecure(false);
        loginPlatform.setHttpOnly(true);

        DefaultJwtBuilder jwtBuilder = new DefaultJwtBuilder("accessToken");
        jwtBuilder.setHeader("alg", SignatureAlgorithm.forSigningKey(accessTokenKey).getValue());
        jwtBuilder.setHeader("typ", "JWT");
        jwtBuilder.setPayload("iss", "sMilestone", "registered");
        jwtBuilder.setPayload("sub", authResult.getName(), "registered");
        jwtBuilder.setPayload("aud", authResult.getName(), "registered");
        jwtBuilder.setPayload("exp", (Instant.now().plusSeconds(1L)).toString(), "registered");
        jwtBuilder.setPayload("iat", Instant.now().toString(), "registered");
        jwtBuilder.setPayload("token_type", "accessToken", "public");

        Cookie accessTokenCookie = new Cookie("accessToken", jwtBuilder.compact());
        accessTokenCookie.setPath("/");
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setHttpOnly(true);

        jwtBuilder = new DefaultJwtBuilder("refreshToken");
        jwtBuilder.setHeader("alg", SignatureAlgorithm.forSigningKey(refreshTokenKey).getValue());
        jwtBuilder.setHeader("typ", "JWT");
        jwtBuilder.setPayload("iss", "sMilestone", "registered");
        jwtBuilder.setPayload("sub", authResult.getName(), "registered");
        jwtBuilder.setPayload("aud", authResult.getName(), "registered");
        jwtBuilder.setPayload("exp", (Instant.now().plusSeconds(3096000L)).toString(), "registered");
        jwtBuilder.setPayload("iat", Instant.now().toString(), "registered");
        jwtBuilder.setPayload("token_type", "refreshToken", "public");

        Cookie refreshTokenCookie = new Cookie("refreshToken", jwtBuilder.compact());
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setHttpOnly(true);

        Cookie loginUser = new Cookie("user", authResult.getName());
        loginUser.setPath("/");
        loginUser.setSecure(false);
        loginUser.setHttpOnly(true);

        Cookie expireAt = new Cookie("expireAt", (Instant.now().plusSeconds(3096000L)).toString());
        expireAt.setPath("/");
        expireAt.setSecure(false);
        expireAt.setHttpOnly(true);

        response.addCookie(loginPlatform);
        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
        response.addCookie(loginUser);
        response.addCookie(expireAt);
    }
}
