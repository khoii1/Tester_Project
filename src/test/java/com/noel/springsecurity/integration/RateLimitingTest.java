package com.noel.springsecurity.integration;

import static org.hamcrest.Matchers.not;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
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
import com.noel.springsecurity.dto.request.ResetPasswordRequest;
import com.noel.springsecurity.dto.request.VerifyOtpRequest;
import com.noel.springsecurity.utils.TestDataBuilder;

/**
 * Integration tests for Rate Limiting functionality
 * Tests the Bucket4j rate limiter on authentication endpoints
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestEmailConfig.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@TestMethodOrder(MethodOrderer.MethodName.class)
class RateLimitingTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static final String LOGIN_ENDPOINT = "/api/v1/auth/login";
    private static final String SEND_OTP_ENDPOINT = "/api/v1/auth/send-otp";
    private static final String VERIFY_OTP_ENDPOINT = "/api/v1/auth/verify-otp";
    private static final String FORGOT_PASSWORD_ENDPOINT = "/api/v1/auth/forgot-password";
    private static final String RESET_PASSWORD_ENDPOINT = "/api/v1/auth/reset-password";

    @Test
    @DisplayName("Should rate limit login endpoint after 5 requests")
    void testLoginRateLimit() throws Exception {
        LoginRequest request = TestDataBuilder.createLoginRequest(
                "test@example.com",
                "WrongPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Send 5 requests - should not be rate limited
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // 6th request should be rate limited
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    @Test
    @DisplayName("Should rate limit send-otp endpoint after 5 requests")
    void testSendOtpRateLimit() throws Exception {
        OtpRequest request = TestDataBuilder.createOtpRequest("test@example.com");
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Send 5 OTP requests
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(SEND_OTP_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // 6th request should be rate limited
        mockMvc.perform(post(SEND_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    @Test
    @DisplayName("Should rate limit verify-otp endpoint after 5 requests")
    void testVerifyOtpRateLimit() throws Exception {
        String email = "test@example.com";

        // Try to brute-force OTP verification
        for (int i = 0; i < 5; i++) {
            VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(
                    email,
                    String.format("%06d", i)
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // 6th attempt should be rate limited
        VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(email, "999999");
        String jsonRequest = objectMapper.writeValueAsString(request);

        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    @Test
    @DisplayName("Should rate limit forgot-password endpoint after 5 requests")
    void testForgotPasswordRateLimit() throws Exception {
        ForgotPasswordRequest request = new ForgotPasswordRequest("victim@example.com");
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Spam password reset requests
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(FORGOT_PASSWORD_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // 6th request should be rate limited
        mockMvc.perform(post(FORGOT_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    @Test
    @DisplayName("Should rate limit reset-password endpoint after 5 requests")
    void testResetPasswordRateLimit() throws Exception {
        // Try multiple reset attempts with different tokens
        for (int i = 0; i < 5; i++) {
            ResetPasswordRequest request = new ResetPasswordRequest(
                    "fake-token-" + i,
                    "NewPassword123!"
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // 6th request should be rate limited
        ResetPasswordRequest request = new ResetPasswordRequest(
                "fake-token-11",
                "NewPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(request);

        mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    @Test
    @DisplayName("Rate limit should reset after waiting period")
    void testRateLimitReset() throws Exception {
        LoginRequest request = TestDataBuilder.createLoginRequest(
                "reset-test@example.com",
                "Password123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Trigger rate limit
        for (int i = 0; i < 6; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(jsonRequest));
        }

        // Verify rate limited
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests());

        // Wait for rate limit window to expire (61 seconds)
        System.out.println("⏳ Waiting 61 seconds for rate limit reset...");
        Thread.sleep(61000);

        // Should be able to make requests again
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().is(not(429)));
    }

    @Test
    @DisplayName("Rate limits should be independent per IP address")
    void testRateLimitPerIP() throws Exception {
        LoginRequest request = TestDataBuilder.createLoginRequest(
                "ip-test@example.com",
                "Password123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Exhaust rate limit for IP A (127.0.0.1)
        for (int i = 0; i < 6; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(jsonRequest));
        }

        // Verify IP A is rate limited
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests());

        // Simulate request from different IP (IP B)
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest)
                        .header("X-Forwarded-For", "192.168.1.100"))
                .andExpect(status().is(not(429))); // Should NOT be rate limited
    }

    @Test
    @DisplayName("Rate limits should be shared across all auth endpoints (per IP)")
    void testMultipleEndpointsIndependent() throws Exception {
        // Exhaust rate limit on login endpoint (5 requests)
        LoginRequest loginRequest = TestDataBuilder.createLoginRequest(
                "multi-endpoint@example.com",
                "Password123!"
        );
        String loginJson = objectMapper.writeValueAsString(loginRequest);

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(loginJson));
        }

        // Verify login is rate limited
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));

        // Send-OTP endpoint should also be rate limited (shared bucket)
        OtpRequest otpRequest = TestDataBuilder.createOtpRequest("multi-endpoint@example.com");
        String otpJson = objectMapper.writeValueAsString(otpRequest);

        mockMvc.perform(post(SEND_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(otpJson))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }
}
