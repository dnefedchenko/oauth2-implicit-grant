package com.freeman.oauth2.configuration.security.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FormBasedAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private JwtService jwtService;

    public FormBasedAuthenticationSuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        response.setHeader("X-Token", generateToken(authentication));
        response.setStatus(HttpStatus.OK.value());
    }

    private String generateToken(Authentication authentication) {
        User principal = (User) authentication.getPrincipal();
        return this.jwtService.generateJwtToken(principal.getUsername());
    }
}
