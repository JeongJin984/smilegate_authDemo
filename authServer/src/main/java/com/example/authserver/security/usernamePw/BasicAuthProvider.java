package com.example.authserver.security.usernamePw;

import com.example.authserver.security.AbstractAuthFilter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class BasicAuthProvider implements AuthenticationProvider {
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    public BasicAuthProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws UsernameNotFoundException {
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(authentication.getName());

            if(!passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword())) {
                throw new BadCredentialsException("Credential InCorrect");
            }

            UsernamePasswordAuthenticationToken result = UsernamePasswordAuthenticationToken.authenticated(
                    userDetails.getUsername(),
                    authentication.getCredentials(),
                    this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities())
            );
            result.setDetails(authentication.getDetails());

            return result;
        } catch (UsernameNotFoundException usernameNotFoundException) {
            throw new UsernameNotFoundException("incorrect username");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
