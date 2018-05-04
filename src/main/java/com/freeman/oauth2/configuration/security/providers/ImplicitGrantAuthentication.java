package com.freeman.oauth2.configuration.security.providers;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ImplicitGrantAuthentication extends AbstractAuthenticationToken {
    private String googleAccessToken;

    public ImplicitGrantAuthentication(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
    }

    public ImplicitGrantAuthentication(Collection<? extends GrantedAuthority> authorities, String googleAccessToken) {
        super(authorities);
        this.googleAccessToken = googleAccessToken;
    }

    @Override
    public Object getCredentials() {
        return String.valueOf("");
    }

    @Override
    public Object getPrincipal() {
        return this.googleAccessToken;
    }
}
