package com.freeman.oauth2.configuration.security.filters;

import com.freeman.oauth2.configuration.security.GoogleUser;
import com.freeman.oauth2.configuration.security.providers.ImplicitGrantAuthentication;
import com.freeman.oauth2.configuration.security.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class ImplicitGrantAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private static Logger logger = LoggerFactory.getLogger(ImplicitGrantAuthenticationFilter.class);

    private String googleAccessTokenParameter = "google_access_token";
    private AuthenticationManager authenticationManager;
    private JwtService jwtService;

    public ImplicitGrantAuthenticationFilter(RequestMatcher processingUrlMatcher) {
        super(processingUrlMatcher);
    }

    public ImplicitGrantAuthenticationFilter(RequestMatcher processingUrlMatcher,
                                             AuthenticationManager authenticationManager, JwtService jwtService) {
        super(processingUrlMatcher);
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        validateRequest(httpServletRequest);
        String googleAccessToken = httpServletRequest.getParameter(googleAccessTokenParameter);
        logger.info("Attempting to authentication google user with access token - {}", googleAccessToken);
        Authentication authentication = new ImplicitGrantAuthentication(
                Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")), googleAccessToken);
        return this.authenticationManager.authenticate(authentication);
    }

    private void validateRequest(HttpServletRequest request) {
        if (!Objects.equals(request.getMethod(), "POST")) {
            throw new RuntimeException("Invalid request method");
        }
        if (StringUtils.isEmpty(request.getParameter(googleAccessTokenParameter))) {
            throw new RuntimeException(String.format("Request parameter missing - %s", googleAccessTokenParameter));
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        response.setHeader("X-Token", generateToken(authResult));
        response.setStatus(HttpStatus.OK.value());
        return;
    }

    private String generateToken(Authentication authResult) {
        String token = "";
        if (authResult.getPrincipal() instanceof GoogleUser) {
            GoogleUser googleUser = (GoogleUser) authResult.getPrincipal();
            Map<String, Object> claims = new HashMap<>();
            claims.put("name", googleUser.getName());
            claims.put("given_name", googleUser.getGiven_name());
            claims.put("family_name", googleUser.getFamily_name());
            claims.put("gender", googleUser.getGender());
            claims.put("authorities", authResult.getAuthorities().stream()
                .map(entry -> (entry.getAuthority()))
                .collect(Collectors.joining(",")));
            token = jwtService.generateJwtToken(googleUser.getEmail(), claims);
        }
        return token;
    }
}
