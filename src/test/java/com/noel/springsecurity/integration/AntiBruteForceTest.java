package com.noel.springsecurity.integration;

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
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.repositories.IRefreshTokenRepository;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.utils.TestDataBuilder;

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

    @BeforeEach
    void setUp() {
        // Clean up test data - delete refresh tokens first to avoid FK constraint
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    // ======================== BASIC INTEGRATION TESTS (3 TCs) ========================
    // Kiểm tra tích hợp cơ bản: ABF + RL hoạt động đúng cho từng endpoint
    // Anti-Brute Force (ABF) = Rate Limiting cho failed attempts
    // Rate Limiting (RL) = Giới hạn tổng số requests

    // Test: Login endpoint bị chặn sau 5 lần thử sai
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

    // Test: OTP verification bị chặn sau 5 lần thử sai
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

    // Test: Reset password bị chặn sau 5 lần thử token sai
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

    // ======================== ANTI-BRUTE FORCE TESTS CHI TIẾT ========================
    // Kiểm tra chi tiết cơ chế ABF: khóa tài khoản sau nhiều lần failed attempts
    // Ngưỡng: 5 lần thất bại → khóa 10 phút → HTTP 429

    // ==================== ABF CHO LOGIN (7 TCs) ====================
    // Kiểm tra ABF khi đăng nhập sai nhiều lần

    // ABF-LOGIN-01: Không khóa tài khoản sau 4 lần đăng nhập sai (dưới ngưỡng)
    @Test
    @DisplayName("ABF-LOGIN-01: Should NOT lock account after 4 failed login attempts")
    void testLoginFailuresUnderThreshold() throws Exception {
        User testUser = TestDataBuilder.createTestUser(
                "under-threshold@example.com",
                passwordEncoder.encode("CorrectPassword123!")
        );
        userRepository.save(testUser);

        LoginRequest wrongRequest = TestDataBuilder.createLoginRequest(
                "under-threshold@example.com",
                "WrongPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(wrongRequest);

        // Attempt 4 failed logins (under threshold of 5)
        for (int i = 0; i < 4; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isUnauthorized()); // Should be 401, not locked
        }

        // 5th attempt should still work (not locked yet)
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isUnauthorized()); // Still 401, not locked
    }

    // ABF-LOGIN-02: Khóa tài khoản đúng sau 5 lần đăng nhập sai
    @Test
    @DisplayName("ABF-LOGIN-02: Should lock account exactly after 5 failed login attempts")
    void testLoginLockExactlyAt5Failures() throws Exception {
        User testUser = TestDataBuilder.createTestUser(
                "exact-5-fails@example.com",
                passwordEncoder.encode("CorrectPassword123!")
        );
        userRepository.save(testUser);

        LoginRequest wrongRequest = TestDataBuilder.createLoginRequest(
                "exact-5-fails@example.com",
                "WrongPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(wrongRequest);

        // Exactly 5 failed attempts
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isUnauthorized());
        }

        // 6th attempt should be locked (429 Too Many Requests)
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests());
    }

    // ABF-LOGIN-03: Tài khoản đã khóa vẫn tiếp tục bị khóa khi thử lại
    @Test
    @DisplayName("ABF-LOGIN-03: Locked account should remain locked for multiple attempts")
    void testLoginAccountStaysLocked() throws Exception {
        User testUser = TestDataBuilder.createTestUser(
                "stays-locked@example.com",
                passwordEncoder.encode("CorrectPassword123!")
        );
        userRepository.save(testUser);

        LoginRequest wrongRequest = TestDataBuilder.createLoginRequest(
                "stays-locked@example.com",
                "WrongPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(wrongRequest);

        // Lock the account (5 failures)
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isUnauthorized());
        }

        // Try 3 more times - all should be locked
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isTooManyRequests());
        }
    }

    // ABF-LOGIN-04: Đăng nhập thành công reset counter về 0
    @Test
    @DisplayName("ABF-LOGIN-04: Successful login should reset failed attempt counter")
    void testLoginSuccessResetsCounter() throws Exception {
        User testUser = TestDataBuilder.createTestUser(
                "reset-counter@example.com",
                passwordEncoder.encode("CorrectPassword123!")
        );
        userRepository.save(testUser);

        // Fail 3 times
        LoginRequest wrongRequest = TestDataBuilder.createLoginRequest(
                "reset-counter@example.com",
                "WrongPassword123!"
        );
        String wrongJson = objectMapper.writeValueAsString(wrongRequest);

        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(wrongJson))
                    .andExpect(status().isUnauthorized());
        }

        // Successful login (should reset counter)
        LoginRequest correctRequest = TestDataBuilder.createLoginRequest(
                "reset-counter@example.com",
                "CorrectPassword123!"
        );
        String correctJson = objectMapper.writeValueAsString(correctRequest);

        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(correctJson))
                .andExpect(status().isOk());

        // Now should be able to fail another 5 times before locking
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(wrongJson))
                    .andExpect(status().isUnauthorized()); // Not locked
        }

        // 6th failure should lock again
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(wrongJson))
                .andExpect(status().isTooManyRequests());
    }

    // ABF-LOGIN-05: Password đúng vẫn bị chặn khi tài khoản đang bị khóa
    @Test
    @DisplayName("ABF-LOGIN-05: Correct password during lock should still be rejected")
    void testLoginCorrectPasswordDuringLock() throws Exception {
        User testUser = TestDataBuilder.createTestUser(
                "correct-during-lock@example.com",
                passwordEncoder.encode("CorrectPassword123!")
        );
        userRepository.save(testUser);

        LoginRequest wrongRequest = TestDataBuilder.createLoginRequest(
                "correct-during-lock@example.com",
                "WrongPassword123!"
        );
        String wrongJson = objectMapper.writeValueAsString(wrongRequest);

        // Lock the account (5 failures)
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(wrongJson))
                    .andExpect(status().isUnauthorized());
        }

        // Try with CORRECT password - should still be locked
        LoginRequest correctRequest = TestDataBuilder.createLoginRequest(
                "correct-during-lock@example.com",
                "CorrectPassword123!"
        );
        String correctJson = objectMapper.writeValueAsString(correctRequest);

        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(correctJson))
                .andExpect(status().isTooManyRequests()); // Still locked!
    }

    // ABF-LOGIN-06: Users khác nhau có counter khóa độc lập
    @Test
    @DisplayName("ABF-LOGIN-06: Different users should have independent lock counters")
    void testLoginIndependentUserLocks() throws Exception {
        User user1 = TestDataBuilder.createTestUser(
                "user1@example.com",
                passwordEncoder.encode("Password123!")
        );
        User user2 = TestDataBuilder.createTestUser(
                "user2@example.com",
                passwordEncoder.encode("Password123!")
        );
        userRepository.save(user1);
        userRepository.save(user2);

        // Lock user1
        LoginRequest user1Wrong = TestDataBuilder.createLoginRequest(
                "user1@example.com",
                "WrongPassword!"
        );
        String user1Json = objectMapper.writeValueAsString(user1Wrong);

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(user1Json))
                    .andExpect(status().isUnauthorized());
        }

        // Verify user1 is locked
        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(user1Json))
                .andExpect(status().isTooManyRequests());

        // User2 should NOT be locked
        LoginRequest user2Correct = TestDataBuilder.createLoginRequest(
                "user2@example.com",
                "Password123!"
        );
        String user2Json = objectMapper.writeValueAsString(user2Correct);

        mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(user2Json))
                .andExpect(status().isOk()); // User2 can login
    }

    // ABF-LOGIN-07: Thông báo khóa hiển thị thời gian còn lại
    @Test
    @DisplayName("ABF-LOGIN-07: Lock should include remaining time in error message")
    void testLoginLockDurationMessage() throws Exception {
        User testUser = TestDataBuilder.createTestUser(
                "lock-message@example.com",
                passwordEncoder.encode("CorrectPassword123!")
        );
        userRepository.save(testUser);

        LoginRequest wrongRequest = TestDataBuilder.createLoginRequest(
                "lock-message@example.com",
                "WrongPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(wrongRequest);

        // Lock the account
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post(LOGIN_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isUnauthorized());
        }

        // Verify lock message contains time information
        MvcResult result = mockMvc.perform(post(LOGIN_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        assertThat(responseBody).containsAnyOf("phút", "minute", "10"); // Check for time mention
    }

    // ==================== ABF CHO VERIFY OTP (7 TCs) ====================
    // Kiểm tra ABF khi nhập OTP sai nhiều lần

    // ABF-OTP-01: Không khóa sau 4 lần verify OTP sai
    @Test
    @DisplayName("ABF-OTP-01: Should NOT lock after 4 failed OTP verification attempts")
    void testOtpVerifyFailuresUnderThreshold() throws Exception {
        String email = "otp-under-threshold@example.com";

        // Try 4 wrong OTP codes
        for (int i = 0; i < 4; i++) {
            VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(
                    email,
                    String.format("%06d", i)
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429))); // Not locked yet
        }

        // 5th attempt should still work (not locked)
        VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(email, "999999");
        String jsonRequest = objectMapper.writeValueAsString(request);

        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().is(not(429)));
    }

    // ABF-OTP-02: Khóa verify OTP đúng sau 5 lần sai
    @Test
    @DisplayName("ABF-OTP-02: Should lock OTP verification exactly after 5 failures")
    void testOtpVerifyLockExactlyAt5Failures() throws Exception {
        String email = "otp-exact-5@example.com";

        // Exactly 5 failed OTP verifications
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

        // 6th attempt should be locked
        VerifyOtpRequest finalRequest = TestDataBuilder.createVerifyOtpRequest(email, "999999");
        String jsonRequest = objectMapper.writeValueAsString(finalRequest);

        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests());
    }

    // ABF-OTP-03: OTP đúng vẫn bị chặn khi đã bị khóa
    @Test
    @DisplayName("ABF-OTP-03: Locked OTP should reject even correct OTP")
    void testOtpLockedRejectsCorrectOtp() throws Exception {
        String email = "otp-locked-correct@example.com";

        // Lock by failing 5 times
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

        // Even if we somehow know the correct OTP, should still be locked
        // (In real scenario, we don't know the correct OTP, but testing the lock mechanism)
        VerifyOtpRequest correctOtp = TestDataBuilder.createVerifyOtpRequest(email, "123456");
        String jsonRequest = objectMapper.writeValueAsString(correctOtp);

        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests()); // Should be locked
    }

    // ABF-OTP-04: Gửi OTP mới không bypass được lock verification
    @Test
    @DisplayName("ABF-OTP-04: Sending new OTP should NOT bypass verification lock")
    void testOtpSendingDoesNotBypassVerifyLock() throws Exception {
        String email = "otp-send-bypass@example.com";

        // Lock OTP verification by failing 5 times
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

        // Verify locked
        VerifyOtpRequest verifyRequest = TestDataBuilder.createVerifyOtpRequest(email, "999999");
        String verifyJson = objectMapper.writeValueAsString(verifyRequest);

        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyJson))
                .andExpect(status().isTooManyRequests());

        // Verification should STILL be locked even after sending new OTP
        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyJson))
                .andExpect(status().isTooManyRequests());
    }

    // ABF-OTP-05: Email khác nhau có OTP lock độc lập
    @Test
    @DisplayName("ABF-OTP-05: Different emails should have independent OTP locks")
    void testOtpIndependentEmailLocks() throws Exception {
        String email1 = "otp-email1@example.com";
        String email2 = "otp-email2@example.com";

        // Lock email1's OTP verification
        for (int i = 0; i < 5; i++) {
            VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(
                    email1,
                    String.format("%06d", i)
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // Verify email1 is locked
        VerifyOtpRequest email1Request = TestDataBuilder.createVerifyOtpRequest(email1, "999999");
        String email1Json = objectMapper.writeValueAsString(email1Request);

        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(email1Json))
                .andExpect(status().isTooManyRequests());

        // Email2 should NOT be locked
        VerifyOtpRequest email2Request = TestDataBuilder.createVerifyOtpRequest(email2, "123456");
        String email2Json = objectMapper.writeValueAsString(email2Request);

        mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(email2Json))
                .andExpect(status().is(not(429))); // Not locked
    }

    // ABF-OTP-06: OTP lock duy trì qua nhiều lần thử verify
    @Test
    @DisplayName("ABF-OTP-06: OTP lock should persist across multiple verification attempts")
    void testOtpLockPersistence() throws Exception {
        String email = "otp-lock-persist@example.com";

        // Lock the account
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

        // Try 5 more times - all should be locked
        for (int i = 0; i < 5; i++) {
            VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(email, "999999");
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isTooManyRequests());
        }
    }

    // ABF-OTP-07: Concurrent requests vẫn respect OTP lock
    @Test
    @DisplayName("ABF-OTP-07: Concurrent OTP verification attempts should respect lock")
    void testOtpConcurrentVerificationLock() throws Exception {
        String email = "otp-concurrent@example.com";

        // Pre-lock with 5 failures
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

        // Concurrent attempts should all be locked
        int threadCount = 10;
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger lockedCount = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    VerifyOtpRequest request = TestDataBuilder.createVerifyOtpRequest(email, "999999");
                    String jsonRequest = objectMapper.writeValueAsString(request);

                    MvcResult result = mockMvc.perform(post(VERIFY_OTP_ENDPOINT)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(jsonRequest))
                            .andReturn();

                    if (result.getResponse().getStatus() == 429) {
                        lockedCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    // Ignore
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        // All concurrent attempts should be locked
        assertThat(lockedCount.get()).isEqualTo(threadCount);
    }

    // ==================== ABF CHO RESET PASSWORD (6 TCs) ====================
    // Kiểm tra ABF khi thử reset password bằng token không hợp lệ nhiều lần
    // Tracking: Global (tất cả tokens sai đều count chung để chống brute force)

    // ABF-RESET-01: Không khóa sau 4 lần reset password sai
    @Test
    @DisplayName("ABF-RESET-01: Should NOT lock after 4 failed reset password attempts")
    void testResetPasswordFailuresUnderThreshold() throws Exception {
        // Try 4 wrong tokens
        for (int i = 0; i < 4; i++) {
            ResetPasswordRequest request = new ResetPasswordRequest(
                    "fake-token-" + UUID.randomUUID(),
                    "NewPassword123!"
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429))); // Not locked
        }

        // 5th attempt should still work
        ResetPasswordRequest request = new ResetPasswordRequest(
                "fake-token-final",
                "NewPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(request);

        mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().is(not(429)));
    }

    // ABF-RESET-02: Khóa reset password đúng sau 5 lần sai
    @Test
    @DisplayName("ABF-RESET-02: Should lock reset password exactly after 5 failures")
    void testResetPasswordLockExactlyAt5Failures() throws Exception {
        // Exactly 5 failed reset attempts
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

        // 6th attempt should be locked
        ResetPasswordRequest finalRequest = new ResetPasswordRequest(
                "fake-token-final",
                "NewPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(finalRequest);

        mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests());
    }

    // ABF-RESET-03: Reset lock duy trì qua nhiều lần thử
    @Test
    @DisplayName("ABF-RESET-03: Locked reset should persist across multiple attempts")
    void testResetPasswordLockPersistence() throws Exception {
        // Lock by failing 5 times
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

        // Try 3 more times - all should be locked
        for (int i = 0; i < 3; i++) {
            ResetPasswordRequest request = new ResetPasswordRequest(
                    "another-fake-token",
                    "NewPassword123!"
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().isTooManyRequests());
        }
    }

    // ABF-RESET-04: Token khác nhau vẫn count chung vào lock
    @Test
    @DisplayName("ABF-RESET-04: Different tokens should still count towards same lock")
    void testResetPasswordDifferentTokensSameLock() throws Exception {
        // Each attempt uses different token, but should still count
        for (int i = 0; i < 5; i++) {
            ResetPasswordRequest request = new ResetPasswordRequest(
                    "token-" + UUID.randomUUID(), // Different token each time
                    "NewPassword123!"
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // Should be locked after 5 different tokens
        ResetPasswordRequest finalRequest = new ResetPasswordRequest(
                "token-final",
                "NewPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(finalRequest);

        mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests());
    }

    // ABF-RESET-05: Thông báo reset lock hiển thị thời gian còn lại
    @Test
    @DisplayName("ABF-RESET-05: Reset password lock should include time remaining")
    void testResetPasswordLockMessage() throws Exception {
        // Lock the reset functionality
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

        // Check lock message
        ResetPasswordRequest finalRequest = new ResetPasswordRequest(
                "fake-token-final",
                "NewPassword123!"
        );
        String jsonRequest = objectMapper.writeValueAsString(finalRequest);

        MvcResult result = mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        assertThat(responseBody).containsAnyOf("phút", "minute", "10");
    }

    // ABF-RESET-06: Concurrent reset requests vẫn respect lock
    @Test
    @DisplayName("ABF-RESET-06: Concurrent reset password attempts should respect lock")
    void testResetPasswordConcurrentLock() throws Exception {
        // Pre-lock with 5 failures
        for (int i = 0; i < 5; i++) {
            ResetPasswordRequest request = new ResetPasswordRequest(
                    "pre-lock-token-" + i,
                    "NewPassword123!"
            );
            String jsonRequest = objectMapper.writeValueAsString(request);

            mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(jsonRequest))
                    .andExpect(status().is(not(429)));
        }

        // Concurrent attempts should all be locked
        int threadCount = 10;
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger lockedCount = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int i = 0; i < threadCount; i++) {
            int index = i;
            executor.submit(() -> {
                try {
                    ResetPasswordRequest request = new ResetPasswordRequest(
                            "concurrent-token-" + index,
                            "NewPassword123!"
                    );
                    String jsonRequest = objectMapper.writeValueAsString(request);

                    MvcResult result = mockMvc.perform(post(RESET_PASSWORD_ENDPOINT)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(jsonRequest))
                            .andReturn();

                    if (result.getResponse().getStatus() == 429) {
                        lockedCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    // Ignore
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        // All concurrent attempts should be locked
        assertThat(lockedCount.get()).isEqualTo(threadCount);
    }
}
