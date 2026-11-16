package com.rikkei.microservice.courseservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_USER_ROLE = "X-User-Role";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Đọc quyền trực tiếp từ Header X-User-Role do Gateway truyền xuống mà không giải mã lại JWT
        String roleHeader = request.getHeader(HEADER_USER_ROLE);

        if (roleHeader != null && !roleHeader.isBlank()) {
            List<SimpleGrantedAuthority> authorities = Arrays.stream(roleHeader.split(","))
                    .map(String::trim)
                    .filter(role -> !role.isEmpty())
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken("gateway-authenticated-user", null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("Xác thực thành công từ Gateway Header '{}': Authorities = {}", HEADER_USER_ROLE, authorities);
        } else {
            log.warn("Không tìm thấy Header '{}' từ request đến {}", HEADER_USER_ROLE, request.getRequestURI());
        }

        filterChain.doFilter(request, response);
    }
}
