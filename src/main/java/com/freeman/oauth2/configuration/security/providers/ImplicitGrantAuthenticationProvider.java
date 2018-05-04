package com.freeman.oauth2.configuration.security.providers;

import com.freeman.oauth2.configuration.security.GoogleUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ImplicitGrantAuthenticationProvider implements AuthenticationProvider {
    private static Logger logger = LoggerFactory.getLogger(ImplicitGrantAuthenticationProvider.class);

    @Autowired private RestTemplate restTemplate;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Authorization", String.format("Bearer %s", authentication.getPrincipal()));
        RequestEntity userInfoRequestEntity =
                new RequestEntity(headers, HttpMethod.GET, URI.create("https://www.googleapis.com/oauth2/v3/userinfo"));
        ResponseEntity<GoogleUser> response = this.restTemplate.exchange(userInfoRequestEntity, GoogleUser.class);
        Set<GrantedAuthority> authorities = authentication.getAuthorities().stream().collect(Collectors.toSet());
        return createAuthenticationFor(response.getBody(), authorities);
    }

    private Authentication createAuthenticationFor(GoogleUser googleUser, Set<GrantedAuthority> authorities) {
        logger.info("Creating successful authentication for: {}", googleUser.toString());
        return new UsernamePasswordAuthenticationToken(googleUser, String.valueOf(""), authorities);
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.isAssignableFrom(ImplicitGrantAuthentication.class);
    }
}
