package com.freeman.oauth2;

import com.freeman.oauth2.controllers.UsersController;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;

@ComponentScan(basePackageClasses = {UsersController.class})
@EnableAutoConfiguration
public class ImplicitGrantFlowApplication {
    public static void main(String[] args) {
        SpringApplication.run(ImplicitGrantFlowApplication.class, args);
    }
}
