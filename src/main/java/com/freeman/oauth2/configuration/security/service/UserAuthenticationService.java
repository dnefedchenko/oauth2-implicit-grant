package com.freeman.oauth2.configuration.security.service;

import com.freeman.oauth2.configuration.security.GoogleUser;
import com.freeman.oauth2.configuration.security.providers.ImplicitGrantAuthentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class UserAuthenticationService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User.builder()
                .username("user")
                .password("$2a$11$sR9z9Q66zWqXMTtEA2EeUOiPlen24ChrNmwDkYCVHYbJ7FR9Oy6D6")
                .authorities("ROLE_USER")
                .build();
    }

    public Map<String, String> userDetails() {
        Map<String, String> userDetails = new HashMap<>();
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken usernamePasswordAuthentication = (UsernamePasswordAuthenticationToken)authentication;
            String username = usernamePasswordAuthentication.getPrincipal().toString();
            userDetails.put("email", username);
        }
        return userDetails;
    }
}
