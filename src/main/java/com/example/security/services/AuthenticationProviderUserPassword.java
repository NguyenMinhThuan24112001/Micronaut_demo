package com.example.security.services;

import com.example.models.User;
import com.example.repository.UserRepository;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.FluxSink;

import java.util.Optional;

//AuthenticationProvider mô phỏng xác thực người dùng
//authenticationRequest - Yêu cầu xác thực
//Publisher<AuthenticationResponse>	authenticate(AuthenticationRequest authenticationRequest)Xác thực người dùng với yêu cầu nhất định.
//public Publisher<AuthenticationResponse> authenticate Xác thực người dùng với yêu cầu nhất định
@Singleton
public class AuthenticationProviderUserPassword implements AuthenticationProvider {
    @Inject
    UserRepository userRepository;
    @Override
    public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest,
                                                          AuthenticationRequest<?, ?> authenticationRequest) {
        return Flux.create(emitter -> {
            Optional<User> user = userRepository.findByUsername(authenticationRequest.getIdentity().toString());
            if (authenticationRequest.getIdentity().equals(user.get().getUsername()) &&//tra về mã thông báo đc yêu cầu và so sánh với username
                    authenticationRequest.getSecret().equals(user.get().getPassword())) { //tra về mã thông báo đc yêu cầu và so sánh với password
                emitter.next(AuthenticationResponse.success((String) authenticationRequest.getIdentity()));
                emitter.complete();
            } else {
                emitter.error(AuthenticationResponse.exception());
            }
        }, FluxSink.OverflowStrategy.ERROR);
    }
}
