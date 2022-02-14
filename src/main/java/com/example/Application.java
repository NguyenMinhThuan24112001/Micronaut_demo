package com.example;

import io.micronaut.runtime.Micronaut;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@OpenAPIDefinition(
        info = @Info(
                title = "demomicronaut",
                version = "0.0"
        )
)
@SecurityScheme(name = "BearerAdmin",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "jwt",
        in = SecuritySchemeIn.HEADER, paramName = "Authorization")
@SecurityRequirement(name = "BearerAdmin")
public class Application {

    public static void main(String[] args) {
        Micronaut.run(Application.class, args);
    }
}
