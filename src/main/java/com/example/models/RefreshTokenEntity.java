package com.example.models;

import io.micronaut.data.annotation.DateCreated;
import io.micronaut.data.annotation.MappedEntity;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.time.Instant;

@Data
@Entity
@MappedEntity // <1>
@NoArgsConstructor

public class RefreshTokenEntity {
    @Id // <2>
    @GeneratedValue // <3>
    private Long id;

    @NotBlank
    private String username;

    @NotBlank
    private String refreshToken;

    @NotNull
    private Boolean revoked;

    @DateCreated // <4>
    @NotNull
    private Instant dateCreated;

}
