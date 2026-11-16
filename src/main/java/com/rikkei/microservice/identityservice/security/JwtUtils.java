package com.rikkei.microservice.identityservice.security;

import com.rikkei.microservice.identityservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtils {

    @Value("${app.jwt.secret:vS6K5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2z}")
    private String jwtSecret;

    @Value("${app.jwt.access-token-expiration:900000}")
    private long accessTokenExpiration; // 15 phút = 900,000 ms

    private Key getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Sinh Access Token bằng JJWT (0.11.5)
     * - Thuật toán: HS256
     * - Hạn sống: 15 phút
     * - Standard Claim: sub (username)
     * - Private Claim: role (STUDENT, INSTRUCTOR, ...)
     * - Bắt buộc có claim: jti (JWT ID - chuỗi ngẫu nhiên duy nhất định danh token)
     */
    public String generateAccessToken(User user) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())    // Standard Claim: jti (JWT ID)
                .setSubject(user.getUsername())         // Standard Claim: sub
                .claim("role", user.getRole())          // Private Claim: role
                .setIssuedAt(now)                       // Standard Claim: iat
                .setExpiration(expiryDate)              // Standard Claim: exp (15 phút)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    public String extractJti(String token) {
        return extractAllClaims(token).getId();
    }
}
