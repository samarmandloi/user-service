package com.pm.userservice.controller;

import com.pm.userservice.dto.requestDto.RegisterRequest;
import com.pm.userservice.dto.requestDto.TokenRequest;
import com.pm.userservice.dto.responseDto.RegisterResponse;
import com.pm.userservice.dto.responseDto.TokenResponse;
import com.pm.userservice.entity.User;
import com.pm.userservice.repository.UserRepository;
import com.pm.userservice.service.JwtTokenService;
import com.pm.userservice.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final long expirationSeconds;
    private final UserService userService;

    public AuthController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenService jwtTokenService,
            @Value("${jwt.expiration-seconds}") long expirationSeconds,
            UserService userService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
        this.expirationSeconds = expirationSeconds;
        this.userService = userService;
    }

    @PostMapping("/token")
    public TokenResponse generateToken(
            @Valid @RequestBody TokenRequest request) {

        String email = request.email()
                .trim()
                .toLowerCase(Locale.ROOT);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid email or password"
                ));

        boolean validPassword = passwordEncoder.matches(
                request.password(),
                user.getPassword()
        );

        if (!validPassword || !Boolean.TRUE.equals(user.getEnabled())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid email or password"
            );
        }

        String accessToken = jwtTokenService.generateToken(
                email,
                user.getRole().name(),
                expirationSeconds
        );

        return new TokenResponse(
                accessToken,
                "Bearer",
                expirationSeconds
        );
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(
            @Valid @RequestBody RegisterRequest request) {

        return userService.register(request);
    }
}