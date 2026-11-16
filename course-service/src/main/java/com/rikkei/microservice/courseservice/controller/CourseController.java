package com.rikkei.microservice.courseservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/courses")
public class CourseController {

    @GetMapping
    public ResponseEntity<?> getAllCourses(@RequestHeader(value = "X-User-Role", required = false) String userRole) {
        return ResponseEntity.ok(Map.of(
                "message", "Lấy danh sách khóa học thành công từ Course-Service",
                "receivedUserRole", userRole != null ? userRole : "NONE",
                "courses", List.of(
                        Map.of("id", 1, "title", "Microservices Architecture with Spring Boot", "instructor", "instructor1"),
                        Map.of("id", 2, "title", "Spring Cloud Gateway & JWT Security", "instructor", "instructor1"),
                        Map.of("id", 3, "title", "PostgreSQL & Database Optimization", "instructor", "instructor1")
                )
        ));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getCourseById(@PathVariable Long id,
                                          @RequestHeader(value = "X-User-Role", required = false) String userRole) {
        return ResponseEntity.ok(Map.of(
                "id", id,
                "title", "Microservices Architecture with Spring Boot",
                "instructor", "instructor1",
                "receivedUserRole", userRole != null ? userRole : "NONE"
        ));
    }
}
