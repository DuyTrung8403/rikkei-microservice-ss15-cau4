package com.rikkei.microservice.courseservice;

import com.rikkei.microservice.courseservice.controller.CourseController;
import com.rikkei.microservice.courseservice.dto.CourseRequest;
import com.rikkei.microservice.courseservice.security.HeaderAuthenticationFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class CourseMethodSecurityTest {

    @Autowired
    private CourseController courseController;

    @Autowired
    private HeaderAuthenticationFilter headerFilter;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private void authenticateWithRole(String role) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                "test-user",
                null,
                List.of(new SimpleGrantedAuthority(role))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Test
    @DisplayName("1. STUDENT được phép xem danh sách khóa học (GET /api/courses)")
    void testGetCourses_WithStudentAuthority_Success() {
        authenticateWithRole("STUDENT");

        ResponseEntity<?> response = courseController.getAllCourses();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    @DisplayName("2. INSTRUCTOR được phép xem danh sách khóa học (GET /api/courses)")
    void testGetCourses_WithInstructorAuthority_Success() {
        authenticateWithRole("INSTRUCTOR");

        ResponseEntity<?> response = courseController.getAllCourses();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    @DisplayName("3. STUDENT KHÔNG ĐƯỢC PHÉP tạo khóa học (POST /api/courses) -> Ném AccessDeniedException (403 Forbidden)")
    void testCreateCourse_WithStudentAuthority_Forbidden() {
        authenticateWithRole("STUDENT");

        CourseRequest request = CourseRequest.builder()
                .title("Unauthorized Course")
                .description("Học sinh cố tình tạo khóa học")
                .instructor("student1")
                .build();

        assertThrows(AccessDeniedException.class, () -> courseController.createCourse(request),
                "Role STUDENT không được phép gọi POST /api/courses, phải ném AccessDeniedException (403)");
    }

    @Test
    @DisplayName("4. INSTRUCTOR ĐƯỢC PHÉP tạo khóa học (POST /api/courses) -> 201 Created")
    void testCreateCourse_WithInstructorAuthority_Success() {
        authenticateWithRole("INSTRUCTOR");

        CourseRequest request = CourseRequest.builder()
                .title("Advanced Microservices")
                .description("Khóa học nâng cao do giảng viên tạo")
                .instructor("instructor1")
                .build();

        ResponseEntity<?> response = courseController.createCourse(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    @DisplayName("5. HeaderAuthenticationFilter đọc quyền từ Header X-User-Role và gán đúng Authority")
    void testHeaderAuthenticationFilter_SetsCorrectAuthority() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-User-Role", "STUDENT");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        headerFilter.doFilter(request, response, filterChain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth, "Authentication phải được gán vào SecurityContext");
        assertTrue(auth.getAuthorities().contains(new SimpleGrantedAuthority("STUDENT")),
                "Authority phải chứa STUDENT");
    }
}
