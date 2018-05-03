package com.freeman.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;

@ComponentScan(basePackages = {"com.freeman.oauth2"})
@EnableAutoConfiguration
public class ImplicitGrantFlowApplication {
    public static void main(String[] args) {
        SpringApplication.run(ImplicitGrantFlowApplication.class, args);
    }
}
