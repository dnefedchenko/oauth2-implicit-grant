package com.freeman.oauth2.configuration.security.filters;

import com.freeman.oauth2.configuration.security.providers.ImplicitGrantAuthentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

public class ImplicitGrantAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private static Logger logger = LoggerFactory.getLogger(ImplicitGrantAuthenticationFilter.class);

    private String googleAccessTokenParameter = "google_access_token";
    private AuthenticationManager authenticationManager;

    public ImplicitGrantAuthenticationFilter(RequestMatcher processingUrlMatcher) {
        super(processingUrlMatcher);
    }

    public ImplicitGrantAuthenticationFilter(RequestMatcher processingUrlMatcher, AuthenticationManager authenticationManager) {
        super(processingUrlMatcher);
        this.authenticationManager = authenticationManager;
    }

    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        validateRequest(httpServletRequest);
        logger.info("Attempting to authentication google user with access token - {}",
                httpServletRequest.getParameter(googleAccessTokenParameter));
        return this.authenticationManager.authenticate(new ImplicitGrantAuthentication(Arrays.asList()));
    }

    private void validateRequest(HttpServletRequest request) {
        if (!Objects.equals(request.getMethod(), "POST")) {
            throw new RuntimeException("Invalid request method");
        }
        if (StringUtils.isEmpty(request.getParameter(googleAccessTokenParameter))) {
            throw new RuntimeException(String.format("Request parameter missing - %s", googleAccessTokenParameter));
        }
    }
}
