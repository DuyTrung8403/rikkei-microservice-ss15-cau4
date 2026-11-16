package com.rikkei.microservice.identityservice.service;

import com.rikkei.microservice.identityservice.dto.AuthResponse;
import com.rikkei.microservice.identityservice.dto.LoginRequest;
import com.rikkei.microservice.identityservice.dto.RegisterRequest;
import com.rikkei.microservice.identityservice.entity.RefreshToken;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public AuthResponse login(LoginRequest request) {
        // 1. Tìm kiếm User theo username trong Database
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Tên đăng nhập hoặc mật khẩu không chính xác"));

        // 2. So sánh mật khẩu gửi lên với mật khẩu đã băm (BCrypt) trong DB
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Tên đăng nhập hoặc mật khẩu không chính xác");
        }

        // 3. Đúng mật khẩu -> Sử dụng JJWT sinh Access Token (HS256, 15 phút, chứa sub, role, jti)
        String accessToken = jwtUtils.generateAccessToken(user);

        // 4. Sinh thêm Refresh Token (chuỗi ngẫu nhiên, sống 7 ngày) và lưu vào bảng refresh_tokens
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        // 5. Trả về client cả cặp Access Token và Refresh Token
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(900L) // 15 phút (900s)
                .build();
    }

    public User register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username đã tồn tại: " + request.getUsername());
        }

        String encodedPassword = passwordEncoder.encode(request.getPassword());
        String role = (request.getRole() == null || request.getRole().trim().isEmpty())
                ? "STUDENT"
                : request.getRole().trim().toUpperCase();

        User user = User.builder()
                .username(request.getUsername())
                .password(encodedPassword)
                .role(role)
                .build();

        return userRepository.save(user);
    }
}
