package com.freeman.oauth2;

import com.freeman.oauth2.configuration.ApplicationConfiguration;
import com.freeman.oauth2.controllers.HomeController;
import com.freeman.oauth2.controllers.UsersController;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ApplicationTest {
    @Autowired private HomeController homeController;
    @Autowired private UsersController usersController;

    @Test
    public void contextLoads() {
        assertThat(homeController).isNotNull();
        assertThat(usersController).isNotNull();
    }
}
