package com.freeman.oauth2.controllers;

import com.freeman.oauth2.configuration.security.service.UserAuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/v1/users")
public class UsersController {
    private UserAuthenticationService userAuthenticationService;

    @Autowired
    public UsersController(UserAuthenticationService userAuthenticationService) {
        this.userAuthenticationService = userAuthenticationService;
    }

    @GetMapping(value = "/user")
    public Map<String, String> userDetails() {
        return this.userAuthenticationService.userDetails();
    }
}
