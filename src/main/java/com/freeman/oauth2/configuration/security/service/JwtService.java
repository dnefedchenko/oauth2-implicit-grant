package com.freeman.oauth2.configuration.security.service;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class JwtService {
    private static Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Value("${jwt.private.key}")
    private String privateKey;

    public String generateJwtToken(String subject) {
        return Jwts.builder()
                .setSubject(subject)
                .signWith(SignatureAlgorithm.HS512, privateKey)
                .compact();
    }

    public String generateJwtToken(String subject, Map<String, Object> claims) {
        return Jwts.builder()
                .setSubject(subject)
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, privateKey)
                .compact();
    }

    public Jws<Claims> parseToken(String compactJws) throws SignatureException {
        return Jwts.parser().setSigningKey(privateKey).parseClaimsJws(compactJws);
    }
}
