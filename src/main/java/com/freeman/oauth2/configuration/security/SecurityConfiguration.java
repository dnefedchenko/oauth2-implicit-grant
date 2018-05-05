package com.freeman.oauth2.configuration.security;

import com.freeman.oauth2.configuration.security.filters.ImplicitGrantAuthenticationFilter;
import com.freeman.oauth2.configuration.security.filters.JwtAuthenticationFilter;
import com.freeman.oauth2.configuration.security.providers.ImplicitGrantAuthenticationProvider;
import com.freeman.oauth2.configuration.security.service.FormBasedAuthenticationFailureHandler;
import com.freeman.oauth2.configuration.security.service.FormBasedAuthenticationSuccessHandler;
import com.freeman.oauth2.configuration.security.service.JwtService;
import com.freeman.oauth2.configuration.security.service.RestfulAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.Filter;
import java.util.Arrays;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private String implicitGrantAuthenticationUrl = "/auth/token";
    private String formBasedAuthenticationUrl = "/auth/login";
    private String jwtProcessingUrl = "/**";

    @Autowired private AuthenticationManager authenticationManager;
    @Autowired private UserDetailsService userDetailsService;
    @Autowired private JwtService jwtService;
    @Autowired private ImplicitGrantAuthenticationProvider implicitGrantAuthenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers(HttpMethod.POST, implicitGrantAuthenticationUrl).permitAll()
                    .anyRequest().authenticated()
                .and()
                    .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
                .and()
                    .cors()
                .and()
                .formLogin()
                    .loginProcessingUrl(formBasedAuthenticationUrl)
                    .successHandler(new FormBasedAuthenticationSuccessHandler())
                    .failureHandler(new FormBasedAuthenticationFailureHandler())
                .permitAll()
                .and()
                    .addFilterAfter(buildOAuth2ImplicitGrantFilter(implicitGrantAuthenticationUrl), LogoutFilter.class)
                    .addFilterAfter(buildJwtFilter(jwtProcessingUrl), ImplicitGrantAuthenticationFilter.class)
                .csrf().disable();
    }

    private Filter buildOAuth2ImplicitGrantFilter(String processingUrl) {
        return new ImplicitGrantAuthenticationFilter(new AntPathRequestMatcher(processingUrl,
                "POST"), this.authenticationManager, this.jwtService);
    }

    private Filter buildJwtFilter(String jwtProcessingUrl) {
        return new JwtAuthenticationFilter(jwtProcessingUrl);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(implicitGrantAuthenticationProvider)
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    @Override
    public UserDetailsService userDetailsServiceBean() throws Exception {
        return super.userDetailsServiceBean();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200", "http://localhost:8080"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
        configuration.setExposedHeaders(Arrays.asList("X-Token"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(11);
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new RestfulAuthenticationEntryPoint();
    }
}
