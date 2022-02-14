package com.example;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest
class DeclarativeHttpClientWithJwtTest {

    @Inject
    AppClient appClient;

    @Test
    void verifyJwtAuthenticationWorksWithDeclarativeClient() throws ParseException {
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password");
        BearerAccessRefreshToken loginRsp = appClient.login(creds);

        assertNotNull(loginRsp);
        assertNotNull(loginRsp.getAccessToken());
        assertTrue(JWTParser.parse(loginRsp.getAccessToken()) instanceof SignedJWT);

        String msg = appClient.home("Bearer " + loginRsp.getAccessToken());
        assertEquals("sherlock", msg);
    }
}