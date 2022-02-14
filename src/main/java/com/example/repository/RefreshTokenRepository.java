package com.example.repository;

import com.example.models.RefreshTokenEntity;
import io.micronaut.data.annotation.Repository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;
import lombok.NonNull;

import javax.transaction.Transactional;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.Optional;

@Repository// <1>
public interface RefreshTokenRepository extends CrudRepository<RefreshTokenEntity, Long> { // <2>

    @Transactional
    RefreshTokenEntity save(@NonNull @NotBlank String username,
                            @NonNull @NotBlank String refreshToken,
                            @NonNull @NotNull Boolean revoked); // <3>

    Optional<RefreshTokenEntity> findByRefreshToken(@NonNull @NotBlank String refreshToken); // <4>

    long updateByUsername(@NonNull @NotBlank String username,
                          @NonNull @NotNull Boolean revoked); // <5>
}