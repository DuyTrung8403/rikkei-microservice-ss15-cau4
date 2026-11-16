package com.rikkei.microservice.gatewayservice;

import com.rikkei.microservice.gatewayservice.config.JwtUtils;
import com.rikkei.microservice.gatewayservice.filter.JwtAuthenticationFilter;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class JwtAuthenticationFilterTest {

    @Autowired
    private JwtAuthenticationFilter filter;

    @Autowired
    private JwtUtils jwtUtils;

    @Value("${jwt.secret}")
    private String jwtSecret;

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    private String generateToken(String username, String role, long expirationMs) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + expirationMs);
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    @DisplayName("1. Chặn request không có Authorization Header -> 401 Unauthorized")
    void testFilter_MissingAuthorizationHeader() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertFalse(chainCalled.get(), "Chain không được gọi khi thiếu header");
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    @DisplayName("2. Chặn request với Token đã hết hạn -> 401 Unauthorized")
    void testFilter_ExpiredToken() {
        // Token đã hết hạn 10 giây trước
        String expiredToken = generateToken("student1", "STUDENT", -10000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertFalse(chainCalled.get(), "Chain không được gọi khi token hết hạn");
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    @DisplayName("3. Chặn request với Token sai chữ ký (wrong signature) -> 401 Unauthorized")
    void testFilter_InvalidSignature() {
        // Sinh token với secret key khác
        Key otherKey = Keys.hmacShaKeyFor("different-secret-key-123456789012345678901234567890".getBytes(StandardCharsets.UTF_8));
        String wrongSignatureToken = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject("hacker")
                .claim("role", "ADMIN")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(otherKey, SignatureAlgorithm.HS256)
                .compact();

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + wrongSignatureToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertFalse(chainCalled.get(), "Chain không được gọi khi sai chữ ký");
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    @DisplayName("4. Cho phép Token hợp lệ (role: STUDENT) và gắn Header X-User-Role: STUDENT")
    void testFilter_ValidToken_Student() {
        String validToken = generateToken("student1", "STUDENT", 900000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses/101")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        AtomicReference<String> forwardedRole = new AtomicReference<>();

        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            forwardedRole.set(ex.getRequest().getHeaders().getFirst("X-User-Role"));
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertTrue(chainCalled.get(), "Chain phải được forward khi token hợp lệ");
        assertEquals("STUDENT", forwardedRole.get(), "Header X-User-Role phải là STUDENT");
    }

    @Test
    @DisplayName("5. Cho phép Token hợp lệ (role: INSTRUCTOR) và gắn Header X-User-Role: INSTRUCTOR")
    void testFilter_ValidToken_Instructor() {
        String validToken = generateToken("instructor1", "INSTRUCTOR", 900000);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        AtomicReference<String> forwardedRole = new AtomicReference<>();

        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            forwardedRole.set(ex.getRequest().getHeaders().getFirst("X-User-Role"));
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertTrue(chainCalled.get(), "Chain phải được forward khi token hợp lệ");
        assertEquals("INSTRUCTOR", forwardedRole.get(), "Header X-User-Role phải là INSTRUCTOR");
    }

    @Test
    @DisplayName("6. Request tới đường dẫn public (/api/auth/login) không bị chặn")
    void testFilter_PublicPath_BypassesFilter() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/auth/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = ex -> {
            chainCalled.set(true);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertTrue(chainCalled.get(), "Đường dẫn public phải đi qua filter mà không cần token");
    }
}
