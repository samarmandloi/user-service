package com.pm.userservice.dto.responseDto;

public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {
}
