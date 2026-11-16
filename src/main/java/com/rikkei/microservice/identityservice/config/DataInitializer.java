package com.rikkei.microservice.identityservice.config;

import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // Tạo tài khoản mẫu STUDENT nếu chưa tồn tại
        if (!userRepository.existsByUsername("student1")) {
            User student = User.builder()
                    .username("student1")
                    .password(passwordEncoder.encode("password123"))
                    .role("STUDENT")
                    .build();
            userRepository.save(student);
            log.info("Initialized default user: student1 / password123 (Role: STUDENT)");
        }

        // Tạo tài khoản mẫu INSTRUCTOR nếu chưa tồn tại
        if (!userRepository.existsByUsername("instructor1")) {
            User instructor = User.builder()
                    .username("instructor1")
                    .password(passwordEncoder.encode("password123"))
                    .role("INSTRUCTOR")
                    .build();
            userRepository.save(instructor);
            log.info("Initialized default user: instructor1 / password123 (Role: INSTRUCTOR)");
        }
    }
}
