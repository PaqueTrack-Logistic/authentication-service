package com.logistics.authentication.karate;

import com.intuit.karate.junit5.Karate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthKarateTest {

    @LocalServerPort
    private int port;

    @Karate.Test
    Karate testAuth() {
        return Karate.run("classpath:karate/auth/auth-login.feature")
                .systemProperty("local.server.port", String.valueOf(port));
    }
}
