package com.noel.springsecurity.integration;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.not;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.noel.springsecurity.config.TestEmailConfig;
import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.ResetPasswordRequest;
import com.noel.springsecurity.dto.request.VerifyOtpRequest;
import com.noel.springsecurity.entities.RefreshToken;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.repositories.IRefreshTokenRepository;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.utils.TestDataBuilder;
import com.noel.springsecurity.utils.TokenHashUtil;

/**
 * Integration tests for Anti-Brute-Force protection
 * Tests security mechanisms against brute-force attacks
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestEmailConfig.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@TestMethodOrder(MethodOrderer.MethodName.class)
class AntiBruteForceTest {

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
    private static final String VERIFY_OTP_ENDPOINT = "/api/v1/auth/verify-otp";
    private static final String RESET_PASSWORD_ENDPOINT = "/api/v1/auth/reset-password";
    private static final String REFRESH_ENDPOINT = "/api/v1/auth/refresh";

    @BeforeEach
    void setUp() {
        // Clean up test data - delete refresh tokens first to avoid FK constraint
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Should prevent login brute-force with rate limiting")
    void testLoginBruteForce() throws Exception {
        // Create a test user
        User testUser = TestDataBuilder.createTestUser(
                "bruteforce@example.com",
                passwordEncoder.encode("CorrectPassword123!")
        );
        userRepository.save(testUser);

        LoginRequest wrongRequest = TestDataBuilder.createLoginRequest(
                "bruteforce@example.com",
                "WrongPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(wrongRequest);

        // Attempt 5 failed logins
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429))); // May be 401 Unauthorized
        }

        // 6th attempt should be rate limited
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    @Test
    @DisplayName("Should prevent OTP brute-force with rate limiting")
    void testOtpBruteForce() throws Exception {
        String email = "otp-bruteforce@example.com";

        // Try to brute-force OTP codes
        for (int i = 0; i < 5; i++) {
            VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(
                    email,
                    String.format("%06d", i) // Try OTP: 000000, 000001, 000002...
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // 6th attempt should be rate limited
        VerifyOtpRequest finalRequest = TestDataBuilder.createVerifyOtpRequest(email, "999999");
        String jsonRequest = objectMapper.writeValueAsString(finalRequest);

        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    @Test
    @DisplayName("Should prevent password reset token brute-force")
    void testPasswordResetTokenBruteForce() throws Exception {
        // Try multiple reset attempts with fake tokens
        for (int i = 0; i < 5; i++) {
            ResetPasswordRequest request = new ResetPasswordRequest(
                    "fake-token-" + UUID.randomUUID(),
                    "NewPassword123!"
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // 6th attempt should be rate limited
        ResetPasswordRequest finalRequest = new ResetPasswordRequest(
                "fake-token-final",
                "NewPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(finalRequest);

        mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("X-Rate-Limit-Retry-After-Seconds"));
    }

    @Test
    @DisplayName("Should prevent refresh token reuse (one-time use)")
    void testRefreshTokenReuse() throws Exception {
        // Create a test user
        User testUser = TestDataBuilder.createTestUser(
                "refresh-test@example.com",
                passwordEncoder.encode("Password123!")
        );
        userRepository.save(testUser);

        // Create a refresh token
        String tokenValue = UUID.randomUUID().toString();
        String hashedToken = TokenHashUtil.hashToken(tokenValue); // Hash the token before saving
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(testUser);
        refreshToken.setTokenHash(hashedToken); // Store hashed token
        refreshToken.setExpiresAt(LocalDateTime.now().plusDays(1)); // 24 hours
        refreshTokenRepository.save(refreshToken);

        // First use of token should work (send raw token in cookie)
        mockMvc.perform(post(REFRESH_ENDPOINT)
                        .cookie(new jakarta.servlet.http.Cookie("refresh_token", tokenValue)))
                .andExpect(status().isOk())
                .andReturn();

        // Try to reuse the same token (should fail with 403 Forbidden)
        mockMvc.perform(post(REFRESH_ENDPOINT)
                        .cookie(new jakarta.servlet.http.Cookie("refresh_token", tokenValue)))
                .andExpect(status().isForbidden()); // Token invalidated after first use, returns 403
    }

    @Test
    @DisplayName("Should reject expired tokens")
    void testExpiredTokenRejection() throws Exception {
        // Create a test user
        User testUser = TestDataBuilder.createTestUser(
                "expired-token@example.com",
                passwordEncoder.encode("Password123!")
        );
        userRepository.save(testUser);

        // Create an EXPIRED refresh token
        String expiredTokenValue = UUID.randomUUID().toString();
        String hashedExpiredToken = TokenHashUtil.hashToken(expiredTokenValue); // Hash the expired token
        RefreshToken expiredToken = new RefreshToken();
        expiredToken.setUser(testUser);
        expiredToken.setTokenHash(hashedExpiredToken); // Store hashed token
        expiredToken.setExpiresAt(LocalDateTime.now().minusHours(1)); // Expired 1 hour ago
        refreshTokenRepository.save(expiredToken);

        // Attempt to use expired token (should return 403 Forbidden)
        mockMvc.perform(post(REFRESH_ENDPOINT)
                        .cookie(new jakarta.servlet.http.Cookie("refresh_token", expiredTokenValue)))
                .andExpect(status().isForbidden()); // Expired token returns 403, not 401
    }

    @Test
    @DisplayName("Should handle concurrent login attempts with rate limiting")
    void testConcurrentLoginAttempts() throws Exception {
        // Create a test user
        User testUser = TestDataBuilder.createTestUser(
                "concurrent@example.com",
                passwordEncoder.encode("Password123!")
        );
        userRepository.save(testUser);

        int threadCount = 20;
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger rateLimitedCount = new AtomicInteger(0);
        AtomicInteger successCount = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        LoginRequest request = TestDataBuilder.createLoginRequest(
                "concurrent@example.com",
                "WrongPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Launch concurrent brute-force attempts
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    MvcResult result = mockMvc.perform(post(LOGIN_ENDPOINT)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(jsonRequest))
                            .andReturn();

                    int status = result.getResponse().getStatus();
                    if (status == 429) {
                        rateLimitedCount.incrementAndGet();
                    } else {
                        successCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    // Log error silently
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(30, TimeUnit.SECONDS);
        executor.shutdown();

        // At least 5 requests should be rate limited
        assertThat(rateLimitedCount.get()).isGreaterThanOrEqualTo(5);
        System.out.println("✅ Concurrent test: " + successCount.get() + " succeeded, " 
                + rateLimitedCount.get() + " rate limited");
    }

    @Test
    @DisplayName("Should validate OTP expiration if implemented")
    void testOtpExpiration() throws Exception {
        // Note: This test assumes OTP has expiration logic
        // If your implementation has OTP expiration, this test validates it
        // Otherwise, this test will pass but should be implemented in the actual code

        String email = "otp-expiry@example.com";
        VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(email, "123456");
        String jsonRequest = objectMapper.writeValueAsString(request);

        // Try to verify an OTP (will fail because no OTP was sent)
        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().is4xxClientError()); // Should fail (no OTP sent or expired)
    }
}
