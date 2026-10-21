package com.pm.userservice.controller;

import com.pm.userservice.dto.requestDto.RegisterRequest;
import com.pm.userservice.dto.responseDto.RegisterResponse;
import com.pm.userservice.service.JwtTokenService;
import com.pm.userservice.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import({
        com.pm.userservice.config.SecurityConfig.class,
        com.pm.userservice.config.PasswordConfig.class
})
class AuthControllerRegistrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private JwtTokenService jwtTokenService;

    @MockitoBean
    private com.pm.userservice.repository.UserRepository userRepository;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void registerShouldReturn201ForValidRequest() throws Exception {
        RegisterRequest request = new RegisterRequest(
                "Samar",
                "samar@example.com",
                "Password123"
        );

        when(userService.register(any(RegisterRequest.class)))
                .thenReturn(new RegisterResponse(
                        UUID.randomUUID(),
                        "Samar",
                        "samar@example.com"
                ));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Samar"))
                .andExpect(jsonPath("$.email").value("samar@example.com"));

        verify(userService).register(any(RegisterRequest.class));
    }

    @Test
    void registerShouldReturn400ForInvalidEmail() throws Exception {
        RegisterRequest request = new RegisterRequest(
                "Samar",
                "not-an-email",
                "Password123"
        );

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(userService);
    }

    @Test
    void registerShouldReturn400ForShortPassword() throws Exception {
        RegisterRequest request = new RegisterRequest(
                "Samar",
                "samar@example.com",
                "short"
        );

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(userService);
    }

    @Test
    void registerShouldReturn400ForBlankName() throws Exception {
        RegisterRequest request = new RegisterRequest(
                " ",
                "samar@example.com",
                "Password123"
        );

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(userService);
    }

    @Test
    void registerShouldReturn409ForDuplicateEmail() throws Exception {
        RegisterRequest request = new RegisterRequest(
                "Samar",
                "samar@example.com",
                "Password123"
        );

        when(userService.register(any(RegisterRequest.class)))
                .thenThrow(new ResponseStatusException(
                        HttpStatus.CONFLICT,
                        "Email is already registered"
                ));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());

        verify(userService).register(any(RegisterRequest.class));
    }
}