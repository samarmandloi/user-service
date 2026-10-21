package com.pm.userservice.service;

import com.pm.userservice.dto.requestDto.RegisterRequest;
import com.pm.userservice.dto.responseDto.RegisterResponse;
import com.pm.userservice.entity.User;
import com.pm.userservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;
    private UserService userService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        userService = new UserService(userRepository, passwordEncoder);
    }

    @Test
    void registerShouldSaveUserWithHashedPassword() {
        RegisterRequest request = new RegisterRequest(
                " Samar ",
                " Samar@Example.com ",
                "Password123"
        );

        when(userRepository.findByEmail("samar@example.com"))
                .thenReturn(Optional.empty());

        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> {
                    User user = invocation.getArgument(0);
                    user.setId(UUID.randomUUID());
                    return user;
                });

        RegisterResponse response = userService.register(request);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());

        User savedUser = captor.getValue();

        assertEquals("Samar", savedUser.getName());
        assertEquals("samar@example.com", savedUser.getEmail());
        assertNotEquals("Password123", savedUser.getPassword());
        assertTrue(passwordEncoder.matches(
                "Password123",
                savedUser.getPassword()
        ));
        assertNotNull(response.id());
        assertEquals("Samar", response.name());
        assertEquals("samar@example.com", response.email());
    }

    @Test
    void registerShouldRejectDuplicateEmail() {
        RegisterRequest request = new RegisterRequest(
                "Samar",
                "samar@example.com",
                "Password123"
        );

        when(userRepository.findByEmail("samar@example.com"))
                .thenReturn(Optional.of(new User()));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> userService.register(request)
        );

        assertEquals(HttpStatus.CONFLICT, exception.getStatusCode());
        verify(userRepository, never()).save(any(User.class));
    }
}