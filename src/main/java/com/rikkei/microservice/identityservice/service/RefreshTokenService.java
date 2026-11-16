package com.rikkei.microservice.identityservice.service;

import com.rikkei.microservice.identityservice.dto.AuthResponse;
import com.rikkei.microservice.identityservice.entity.RefreshToken;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.exception.TokenRefreshException;
import com.rikkei.microservice.identityservice.repository.RefreshTokenRepository;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${app.jwt.refresh-token-expiration:604800000}")
    private long refreshTokenDurationMs; // 7 ngày = 604,800,000 ms

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    /**
     * Sinh Refresh Token ban đầu khi người dùng đăng nhập thành công
     */
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        // Xóa token cũ nếu có để đảm bảo tính duy nhất và không bị xung đột khóa ngoại
        refreshTokenRepository.findByUser(user).ifPresent(oldToken -> {
            refreshTokenRepository.delete(oldToken);
            refreshTokenRepository.flush();
        });

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Kiểm tra thời hạn sống của Refresh Token
     */
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            throw new TokenRefreshException(token.getToken(), "Refresh token đã hết hạn sử dụng. Vui lòng đăng nhập lại!");
        }
        return token;
    }

    /**
     * Thực hiện đổi Refresh Token lấy Access Token mới kèm cơ chế Token Rotation
     */
    @Transactional
    public AuthResponse refreshToken(String requestRefreshToken) {
        if (requestRefreshToken == null || requestRefreshToken.isBlank()) {
            throw new TokenRefreshException("", "Chuỗi refreshToken không được để trống!");
        }

        // 1. Truy vấn Database tìm bản ghi chứa refreshToken
        RefreshToken oldToken = refreshTokenRepository.findByToken(requestRefreshToken)
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token không tồn tại trong hệ thống hoặc đã bị xoay vòng (đã được sử dụng trước đó)!"));

        // 2. Kiểm tra nếu token đã quá hạn -> Ném ngoại lệ từ chối
        verifyExpiration(oldToken);

        User user = oldToken.getUser();

        // 3. Cơ chế Token Rotation: Xóa hẳn bản ghi Refresh Token cũ khỏi DB để ngăn ngừa sử dụng lại
        log.info("Thực hiện xoay vòng (Rotation) Refresh Token cũ '{}' của user '{}'", oldToken.getToken(), user.getUsername());
        refreshTokenRepository.delete(oldToken);
        refreshTokenRepository.flush();

        // 4. Sinh một Refresh Token hoàn toàn mới và lưu vào DB
        RefreshToken newRefreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .build();
        newRefreshToken = refreshTokenRepository.save(newRefreshToken);

        // 5. Sinh một Access Token mới bằng JJWT
        String newAccessToken = jwtUtils.generateAccessToken(user);

        log.info("Cấp phát thành công cặp Token mới cho user '{}'", user.getUsername());

        // 6. Trả về cặp Token mới cho Client
        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(900L) // 15 phút (900 giây)
                .build();
    }
}
