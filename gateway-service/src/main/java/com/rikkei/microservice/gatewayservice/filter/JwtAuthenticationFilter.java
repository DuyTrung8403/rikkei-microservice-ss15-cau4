package com.rikkei.microservice.gatewayservice.filter;

import com.rikkei.microservice.gatewayservice.config.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Chỉ áp dụng chặn và kiểm tra JWT đối với các request định tuyến tới /api/courses/**
        if (!path.startsWith("/api/courses")) {
            return chain.filter(exchange);
        }

        // 1. Kiểm tra sự tồn tại của Header Authorization
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || authHeader.isBlank()) {
            log.warn("Chặn request đến {}: Không tìm thấy Authorization Header", path);
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Thiếu Authorization Header");
        }

        if (!authHeader.startsWith("Bearer ")) {
            log.warn("Chặn request đến {}: Authorization Header không đúng định dạng Bearer", path);
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Authorization Header phải có định dạng 'Bearer <token>'");
        }

        String token = authHeader.substring(7).trim();

        // 2. Dùng chung Secret Key với Identity Service để giải mã và kiểm tra JWT
        Claims claims;
        try {
            claims = jwtUtils.extractAllClaims(token);
        } catch (ExpiredJwtException ex) {
            log.warn("Chặn request đến {}: Token đã hết hạn. Chi tiết: {}", path, ex.getMessage());
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token đã hết hạn");
        } catch (SignatureException | SecurityException ex) {
            log.warn("Chặn request đến {}: Sai chữ ký Token. Chi tiết: {}", path, ex.getMessage());
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Chữ ký Token không hợp lệ");
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            log.warn("Chặn request đến {}: Token không hợp lệ. Chi tiết: {}", path, ex.getMessage());
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token không hợp lệ hoặc bị lỗi định dạng");
        }

        // 3. Nếu Token hợp lệ, trích xuất role từ Payload và gắn vào Header mới X-User-Role
        String role = claims.get("role", String.class);
        if (role == null || role.isBlank()) {
            role = "UNKNOWN";
        }

        log.info("Xác thực JWT thành công cho user '{}', role '{}'. Forward request tới Course-Service...",
                claims.getSubject(), role);

        // Gắn Header X-User-Role vào request trước khi forward xuống Course-Service
        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-User-Role", role)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    /**
     * Trả về phản hồi lỗi 401 Unauthorized dạng JSON ngay tại cổng Gateway
     */
    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String errorMessage) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = """
                {
                    "status": %d,
                    "error": "%s",
                    "message": "%s"
                }
                """.formatted(status.value(), status.getReasonPhrase(), errorMessage);

        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        // Ưu tiên chạy trước các filter định tuyến
        return -1;
    }
}
