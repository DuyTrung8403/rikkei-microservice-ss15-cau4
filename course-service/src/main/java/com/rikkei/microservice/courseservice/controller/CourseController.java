package com.rikkei.microservice.courseservice.controller;

import com.rikkei.microservice.courseservice.dto.CourseRequest;
import com.rikkei.microservice.courseservice.model.Course;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RestController
@RequestMapping("/api/courses")
public class CourseController {

    // Danh sách Java List tĩnh lưu trữ dữ liệu khóa học trong bộ nhớ (không dùng Database)
    private static final List<Course> COURSE_LIST = new CopyOnWriteArrayList<>();
    private static final AtomicLong ID_GENERATOR = new AtomicLong(2);

    static {
        COURSE_LIST.add(new Course(1L, "Microservices Architecture with Spring Boot", "Khóa học thiết kế hệ thống Microservices hiện đại", "instructor1"));
        COURSE_LIST.add(new Course(2L, "Spring Cloud Gateway & JWT Security", "Bảo mật và phân quyền hệ thống Microservices", "instructor1"));
    }

    /**
     * API GET /api/courses: Xem danh sách khóa học
     * Đánh dấu: @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
     */
    @GetMapping
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public ResponseEntity<?> getAllCourses() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Thực thi GET /api/courses thành công với authorities: {}", auth.getAuthorities());

        return ResponseEntity.ok(Map.of(
                "status", 200,
                "message", "Lấy danh sách khóa học thành công",
                "currentAuthorities", auth.getAuthorities(),
                "totalCourses", COURSE_LIST.size(),
                "data", COURSE_LIST
        ));
    }

    /**
     * API POST /api/courses: Tạo khóa học mới
     * Đánh dấu: @PreAuthorize("hasAuthority('INSTRUCTOR')")
     */
    @PostMapping
    @PreAuthorize("hasAuthority('INSTRUCTOR')")
    public ResponseEntity<?> createCourse(@RequestBody CourseRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Thực thi POST /api/courses thành công với authorities: {}", auth.getAuthorities());

        Course newCourse = Course.builder()
                .id(ID_GENERATOR.incrementAndGet())
                .title(request.getTitle())
                .description(request.getDescription())
                .instructor(request.getInstructor() != null ? request.getInstructor() : "instructor1")
                .build();

        COURSE_LIST.add(newCourse);

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "status", 201,
                "message", "Tạo khóa học mới thành công",
                "currentAuthorities", auth.getAuthorities(),
                "data", newCourse
        ));
    }
}
