package com.freeman.oauth2.configuration.security.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

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
}
