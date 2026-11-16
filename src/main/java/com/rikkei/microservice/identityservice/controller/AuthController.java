package com.rikkei.microservice.identityservice.controller;

import com.rikkei.microservice.identityservice.dto.AuthResponse;
import com.rikkei.microservice.identityservice.dto.LoginRequest;
import com.rikkei.microservice.identityservice.dto.RefreshTokenRequest;
import com.rikkei.microservice.identityservice.dto.RegisterRequest;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.service.AuthService;
import com.rikkei.microservice.identityservice.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    /**
     * API POST /api/auth/login
     * So sánh mật khẩu băm BCrypt, sinh Access Token (HS256, 15 phút, claims: sub, role, jti)
     * và Refresh Token (ngẫu nhiên, 7 ngày, lưu DB), trả về cặp token cho client.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * API POST /api/auth/register
     * Đăng ký người dùng mới với mật khẩu được mã hóa BCrypt
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        User user = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "role", user.getRole(),
                "message", "Đăng ký người dùng thành công"
        ));
    }

    /**
     * API POST /api/auth/refresh
     * Cấp mới Access Token khi có Refresh Token hợp lệ
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        AuthResponse response = refreshTokenService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }
}
