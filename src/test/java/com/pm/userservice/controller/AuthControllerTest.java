package com.pm.userservice.controller;

import com.pm.userservice.config.PasswordConfig;
import com.pm.userservice.config.SecurityConfig;
import com.pm.userservice.dto.requestDto.TokenRequest;
import com.pm.userservice.entity.User;
import com.pm.userservice.repository.UserRepository;
import com.pm.userservice.service.JwtTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;
import com.pm.userservice.service.UserService;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, PasswordConfig.class})
@TestPropertySource(properties = "jwt.expiration-seconds=300")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private JwtTokenService jwtTokenService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private UserService userService;

    @Test
    void generateTokenShouldReturn200ForValidCredentials() throws Exception {
        TokenRequest request =
                new TokenRequest("samar@example.com", "Password123");

        User user = mock(User.class);

        when(userRepository.findByEmail("samar@example.com"))
                .thenReturn(Optional.of(user));
        when(user.getPassword())
                .thenReturn(passwordEncoder.encode("Password123"));
        when(user.getEnabled()).thenReturn(true);

        when(jwtTokenService.generateToken(
                eq("samar@example.com"), eq(300L)))
                .thenReturn("test-jwt-token");

        mockMvc.perform(post("/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken")
                        .value("test-jwt-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(300));

        verify(userRepository).findByEmail("samar@example.com");
        verify(jwtTokenService)
                .generateToken("samar@example.com", 300L);
    }

    @Test
    void generateTokenShouldReturn401ForUnknownEmail() throws Exception {
        TokenRequest request =
                new TokenRequest("unknown@example.com", "Password123");

        when(userRepository.findByEmail("unknown@example.com"))
                .thenReturn(Optional.empty());

        mockMvc.perform(post("/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());

        verify(userRepository).findByEmail("unknown@example.com");
        verifyNoInteractions(jwtTokenService);
    }

    @Test
    void generateTokenShouldReturn401ForIncorrectPassword() throws Exception {
        TokenRequest request =
                new TokenRequest("samar@example.com", "WrongPassword123");

        User user = mock(User.class);

        when(userRepository.findByEmail("samar@example.com"))
                .thenReturn(Optional.of(user));
        when(user.getPassword())
                .thenReturn(passwordEncoder.encode("Password123"));
        when(user.getEnabled()).thenReturn(true);

        mockMvc.perform(post("/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(jwtTokenService);
    }

    @Test
    void generateTokenShouldReturn401ForDisabledUser() throws Exception {
        TokenRequest request =
                new TokenRequest("samar@example.com", "Password123");

        User user = mock(User.class);

        when(userRepository.findByEmail("samar@example.com"))
                .thenReturn(Optional.of(user));
        when(user.getPassword())
                .thenReturn(passwordEncoder.encode("Password123"));
        when(user.getEnabled()).thenReturn(false);

        mockMvc.perform(post("/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(jwtTokenService);
    }

    @Test
    void generateTokenShouldReturn400ForInvalidEmail() throws Exception {
        TokenRequest request =
                new TokenRequest("not-an-email", "Password123");

        mockMvc.perform(post("/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(userRepository, jwtTokenService);
    }
}