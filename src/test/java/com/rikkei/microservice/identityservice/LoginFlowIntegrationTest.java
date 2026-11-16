package com.rikkei.microservice.identityservice;

import com.rikkei.microservice.identityservice.dto.AuthResponse;
import com.rikkei.microservice.identityservice.dto.LoginRequest;
import com.rikkei.microservice.identityservice.entity.RefreshToken;
import com.rikkei.microservice.identityservice.repository.RefreshTokenRepository;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.security.JwtUtils;
import com.rikkei.microservice.identityservice.service.AuthService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class LoginFlowIntegrationTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("Kiểm thử Đăng nhập thành công với tài khoản STUDENT: sinh Access Token chứa sub, role, jti và lưu Refresh Token trong DB")
    void testLoginSuccess_Student() {
        LoginRequest request = LoginRequest.builder()
                .username("student1")
                .password("password123")
                .build();

        AuthResponse response = authService.login(request);

        assertNotNull(response, "Response không được null");
        assertNotNull(response.getAccessToken(), "Access token không được null");
        assertNotNull(response.getRefreshToken(), "Refresh token không được null");
        assertEquals("Bearer", response.getTokenType());

        // 1. Kiểm tra Access Token bằng JJWT
        Claims claims = jwtUtils.extractAllClaims(response.getAccessToken());

        // Standard claim: sub
        assertEquals("student1", claims.getSubject(), "Claim 'sub' phải là username (student1)");

        // Private claim: role
        assertEquals("STUDENT", claims.get("role", String.class), "Claim 'role' phải là STUDENT");

        // Bắt buộc claim: jti (JWT ID)
        assertNotNull(claims.getId(), "Bắt buộc phải có claim 'jti' (JWT ID)");
        assertFalse(claims.getId().isBlank(), "Claim 'jti' không được để trống");

        // Thời gian sống: 15 phút (900,000 ms)
        Date iat = claims.getIssuedAt();
        Date exp = claims.getExpiration();
        assertNotNull(iat, "Claim 'iat' không được null");
        assertNotNull(exp, "Claim 'exp' không được null");
        long duration = exp.getTime() - iat.getTime();
        assertEquals(900000L, duration, "Access Token phải sống đúng 15 phút (900,000 ms)");

        // 2. Kiểm tra Refresh Token trong PostgreSQL (bảng refresh_tokens)
        Optional<RefreshToken> storedToken = refreshTokenRepository.findByToken(response.getRefreshToken());
        assertTrue(storedToken.isPresent(), "Refresh token phải tồn tại trong bảng refresh_tokens");
        assertEquals("student1", storedToken.get().getUser().getUsername());
        assertTrue(storedToken.get().getExpiryDate().isAfter(Instant.now()), "Refresh token phải còn hạn 7 ngày");
    }

    @Test
    @DisplayName("Kiểm thử Đăng nhập thành công với tài khoản INSTRUCTOR: claim role phải là INSTRUCTOR")
    void testLoginSuccess_Instructor() {
        LoginRequest request = LoginRequest.builder()
                .username("instructor1")
                .password("password123")
                .build();

        AuthResponse response = authService.login(request);

        assertNotNull(response);
        Claims claims = jwtUtils.extractAllClaims(response.getAccessToken());
        assertEquals("instructor1", claims.getSubject());
        assertEquals("INSTRUCTOR", claims.get("role", String.class));
        assertNotNull(claims.getId(), "Claim 'jti' phải tồn tại");
    }

    @Test
    @DisplayName("Kiểm thử Đăng nhập thất bại: sai mật khẩu ném BadCredentialsException")
    void testLoginFailure_WrongPassword() {
        LoginRequest request = LoginRequest.builder()
                .username("student1")
                .password("wrong_password")
                .build();

        assertThrows(BadCredentialsException.class, () -> authService.login(request));
    }

    @Test
    @DisplayName("Kiểm thử Đăng nhập thất bại: username không tồn tại ném BadCredentialsException")
    void testLoginFailure_UserNotFound() {
        LoginRequest request = LoginRequest.builder()
                .username("non_existent_user")
                .password("password123")
                .build();

        assertThrows(BadCredentialsException.class, () -> authService.login(request));
    }
}
