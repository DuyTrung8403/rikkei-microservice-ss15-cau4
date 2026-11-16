package com.rikkei.microservice.identityservice.service;

import com.rikkei.microservice.identityservice.dto.AuthResponse;
import com.rikkei.microservice.identityservice.entity.RefreshToken;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.repository.RefreshTokenRepository;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${app.jwt.refresh-token-expiration:604800000}")
    private long refreshTokenDurationMs; // 7 ngày = 604,800,000 ms

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    /**
     * Sinh Refresh Token (chuỗi ngẫu nhiên, sống 7 ngày)
     * và lưu thông tin này vào bảng refresh_tokens trong Database
     */
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        // Tìm xem user đã có refresh token chưa, nếu có thì tái sử dụng bản ghi và update token mới
        RefreshToken refreshToken = refreshTokenRepository.findByUser(user)
                .orElse(RefreshToken.builder()
                        .user(user)
                        .build());

        // Sinh chuỗi ngẫu nhiên (UUID) sống trong 7 ngày
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token đã hết hạn. Vui lòng đăng nhập lại!");
        }
        return token;
    }

    @Transactional
    public AuthResponse refreshToken(String requestRefreshToken) {
        RefreshToken token = refreshTokenRepository.findByToken(requestRefreshToken)
                .map(this::verifyExpiration)
                .orElseThrow(() -> new RuntimeException("Refresh token không hợp lệ hoặc không tồn tại trong hệ thống!"));

        User user = token.getUser();
        String newAccessToken = jwtUtils.generateAccessToken(user);

        // Cập nhật chuỗi token mới (Refresh Token Rotation)
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshTokenRepository.save(token);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(token.getToken())
                .tokenType("Bearer")
                .expiresIn(900L)
                .build();
    }
}
