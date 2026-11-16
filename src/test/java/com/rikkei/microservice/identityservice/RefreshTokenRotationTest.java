package com.rikkei.microservice.identityservice;

import com.rikkei.microservice.identityservice.dto.AuthResponse;
import com.rikkei.microservice.identityservice.dto.LoginRequest;
import com.rikkei.microservice.identityservice.entity.RefreshToken;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.exception.TokenRefreshException;
import com.rikkei.microservice.identityservice.repository.RefreshTokenRepository;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.security.JwtUtils;
import com.rikkei.microservice.identityservice.service.AuthService;
import com.rikkei.microservice.identityservice.service.RefreshTokenService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class RefreshTokenRotationTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Test
    @DisplayName("Kiểm thử đầy đủ cơ chế Token Rotation: Đổi token thành công, xóa token cũ, ngăn chặn sử dụng lại token cũ (403)")
    void testRefreshTokenRotation_CompleteFlow() {
        // 1. Đăng nhập để lấy Refresh Token ban đầu
        LoginRequest loginRequest = LoginRequest.builder()
                .username("student1")
                .password("password123")
                .build();

        AuthResponse initialLogin = authService.login(loginRequest);
        String oldRefreshToken = initialLogin.getRefreshToken();
        String initialAccessToken = initialLogin.getAccessToken();

        assertNotNull(oldRefreshToken);
        assertTrue(refreshTokenRepository.findByToken(oldRefreshToken).isPresent(),
                "Token ban đầu phải tồn tại trong Database");

        // 2. Gửi Refresh Token cũ vào hàm refreshToken -> Nhận cặp Token mới
        AuthResponse rotatedResponse = refreshTokenService.refreshToken(oldRefreshToken);

        String newRefreshToken = rotatedResponse.getRefreshToken();
        String newAccessToken = rotatedResponse.getAccessToken();

        assertNotNull(newRefreshToken);
        assertNotNull(newAccessToken);
        assertNotEquals(oldRefreshToken, newRefreshToken, "Refresh token mới phải khác Refresh token cũ (Rotation)");
        assertNotEquals(initialAccessToken, newAccessToken, "Access token mới phải khác Access token cũ");

        // Kiểm tra Access Token mới có đủ claims sub, role, jti
        Claims newClaims = jwtUtils.extractAllClaims(newAccessToken);
        assertEquals("student1", newClaims.getSubject());
        assertEquals("STUDENT", newClaims.get("role", String.class));
        assertNotNull(newClaims.getId());

        // Kiểm tra Database:
        // Bản ghi chứa oldRefreshToken PHẢI BỊ XÓA (ngăn ngừa sử dụng lại)
        Optional<RefreshToken> oldTokenInDb = refreshTokenRepository.findByToken(oldRefreshToken);
        assertFalse(oldTokenInDb.isPresent(), "Refresh token cũ phải bị xóa khỏi Database sau khi xoay vòng");

        // Bản ghi chứa newRefreshToken PHẢI TỒN TẠI trong Database
        Optional<RefreshToken> newTokenInDb = refreshTokenRepository.findByToken(newRefreshToken);
        assertTrue(newTokenInDb.isPresent(), "Refresh token mới phải được lưu trong Database");
        assertEquals("student1", newTokenInDb.get().getUser().getUsername());

        // 3. Gửi lại chính Refresh Token cũ đó một lần nữa -> Hệ thống từ chối (ném TokenRefreshException dẫn tới 403)
        assertThrows(TokenRefreshException.class, () -> {
            refreshTokenService.refreshToken(oldRefreshToken);
        }, "Sử dụng lại Refresh Token cũ phải bị từ chối vì token đã bị xoay vòng");

        // 4. Nếu dùng Refresh Token mới vừa sinh -> Cho phép xoay vòng tiếp tục thành công
        AuthResponse secondRotation = refreshTokenService.refreshToken(newRefreshToken);
        assertNotNull(secondRotation.getRefreshToken());
        assertNotEquals(newRefreshToken, secondRotation.getRefreshToken());
    }

    @Test
    @DisplayName("Kiểm thử Refresh Token đã hết hạn -> Ném TokenRefreshException (403)")
    void testRefreshToken_Expired_ThrowsException() {
        User user = userRepository.save(User.builder()
                .username("expired_user_" + UUID.randomUUID())
                .password("password123")
                .role("STUDENT")
                .build());

        // Tạo một token giả định đã hết hạn 1 giờ trước
        RefreshToken expiredToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().minusSeconds(3600))
                .build();
        expiredToken = refreshTokenRepository.save(expiredToken);

        String expiredTokenStr = expiredToken.getToken();

        assertThrows(TokenRefreshException.class, () -> {
            refreshTokenService.refreshToken(expiredTokenStr);
        }, "Token hết hạn phải bị từ chối với TokenRefreshException (403)");
    }
}
