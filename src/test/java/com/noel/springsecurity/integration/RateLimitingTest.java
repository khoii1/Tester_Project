package com.noel.springsecurity.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.noel.springsecurity.config.TestEmailConfig;
import com.noel.springsecurity.dto.request.ForgotPasswordRequest;
import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.OtpRequest;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.repositories.IRefreshTokenRepository;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.utils.TestDataBuilder;

/**
 * Integration tests cho Rate Limiting
 * Kiểm tra giới hạn tổng số requests (cả success + failed)
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestEmailConfig.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class RateLimitingTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private IUserRepository userRepository;

    @Autowired
    private IRefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String LOGIN_ENDPOINT = "/api/v1/auth/login";
    private static final String SEND_OTP_ENDPOINT = "/api/v1/auth/send-otp";
    private static final String FORGOT_PASSWORD_ENDPOINT = "/api/v1/auth/forgot-password";

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    // ==================== RATE LIMITING TESTS (5 TCs) ====================
    // Kiểm tra giới hạn requests THÀNH CÔNG (không phải failed attempts)
    // Giới hạn: 10 requests/phút/IP → Request thứ 11 bị chặn

    // RL-01: Login thành công nhiều lần bị rate limit
    @Test
    @DisplayName("RL-01: Should rate limit successful login requests after 10 attempts")
    void testSuccessfulLoginRateLimit() throws Exception {
        // Tạo user hợp lệ
        User testUser = TestDataBuilder.createTestUser(
                "rate-limit@example.com",
                passwordEncoder.encode("Password123!")
        );
        userRepository.save(testUser);

        LoginRequest validRequest = TestDataBuilder.createLoginRequest(
                "rate-limit@example.com",
                "Password123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(validRequest);

        // Gửi 10 login thành công
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isOk()); // Should succeed
        }

        // Request thứ 11 phải bị rate limit
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    // RL-02: Send OTP nhiều lần bị rate limit
    @Test
    @DisplayName("RL-02: Should rate limit send-OTP requests after 10 attempts")
    void testSendOtpRateLimit() throws Exception {
        OtpRequest request = new OtpRequest("send-otp-test@example.com");
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Gửi 10 send-OTP requests
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post(SEND_OTP_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isOk());
        }

        // Request thứ 11 phải bị rate limit
        mockMvc.perform(post(SEND_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    // RL-03: Forgot password nhiều lần bị rate limit
    @Test
    @DisplayName("RL-03: Should rate limit forgot-password requests after 10 attempts")
    void testForgotPasswordRateLimit() throws Exception {
        // Tạo user để forgot password
        User testUser = TestDataBuilder.createTestUser(
                "forgot-pw-limit@example.com",
                passwordEncoder.encode("Password123!")
        );
        userRepository.save(testUser);

        ForgotPasswordRequest request = new ForgotPasswordRequest("forgot-pw-limit@example.com");
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Gửi 10 forgot-password requests
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post(FORGOT_PASSWORD_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isOk());
        }

        // Request thứ 11 phải bị rate limit
        mockMvc.perform(post(FORGOT_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    // RL-04: Rate limit độc lập cho mỗi endpoint
    @Test
    @DisplayName("RL-04: Different endpoints should have independent rate limits")
    void testIndependentEndpointRateLimits() throws Exception {
        User testUser = TestDataBuilder.createTestUser(
                "multi-endpoint@example.com",
                passwordEncoder.encode("Password123!")
        );
        userRepository.save(testUser);

        // Gửi 10 login requests (max out login endpoint)
        LoginRequest loginRequest = TestDataBuilder.createLoginRequest(
                "multi-endpoint@example.com",
                "Password123!"
        );
        String loginJson = objectMapper.writeValueAsString(loginRequest);

        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson))
                    .andExpect(status().isOk());
        }

        // Login endpoint bị limit
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isTooManyRequests());

        // Forgot password endpoint vẫn hoạt động (bucket riêng)
        ForgotPasswordRequest forgotRequest = new ForgotPasswordRequest("multi-endpoint@example.com");
        String forgotJson = objectMapper.writeValueAsString(forgotRequest);

        mockMvc.perform(post(FORGOT_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(forgotJson))
                .andExpect(status().isOk()); // Vẫn OK vì bucket khác
    }
}
