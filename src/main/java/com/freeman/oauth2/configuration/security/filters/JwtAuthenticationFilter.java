package com.freeman.oauth2.configuration.security.filters;

import com.freeman.oauth2.configuration.security.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.SignatureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private static String AUTHORIZATION_HEADER = "Authorization";
    private JwtService jwtService;

    public JwtAuthenticationFilter(String processingUrl, JwtService jwtService) {
        super(processingUrl);
        this.jwtService = jwtService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!containsAuthorizationHeader(request)) {
            return null;
        }
        Jws<Claims> claims = extractClaims(request);
        String username = claims.getBody().getSubject();
        String authorityClaims = claims.getBody().get("authorities").toString();
        String[] authoritiesArray = authorityClaims.split(",");
        List<GrantedAuthority> authorities = Stream.of(authoritiesArray).map(authority -> new SimpleGrantedAuthority(authority)).collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(username, String.valueOf(""), authorities);
    }

    private boolean containsAuthorizationHeader(HttpServletRequest request) {
        return !StringUtils.isEmpty(request.getHeader(AUTHORIZATION_HEADER));
    }

    private Jws<Claims> extractClaims(HttpServletRequest request) {
        String bearerHeader = request.getHeader(AUTHORIZATION_HEADER);
        String jwtToken = bearerHeader.substring("Bearer ".length());
        Jws<Claims> claims;
        try {
            claims = jwtService.parseToken(jwtToken);
        } catch (SignatureException e) {
            logger.error("Token validation failed {}", e);
            throw new RuntimeException(e);
        }
        return claims;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(authResult);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }
}
