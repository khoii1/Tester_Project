package com.noel.springsecurity.services;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.noel.springsecurity.exceptions.AccountLockedException;

import lombok.extern.slf4j.Slf4j;

/**
 * Anti-Bruteforce Service
 * Tracks failed authentication attempts per email + action
 * Locks account after 5 failed attempts within 10 minutes
 * Lock duration: 10 minutes
 */
@Service
@Slf4j
public class AntiBruteForceService {

    private static final int MAX_ATTEMPTS = 5;
    private static final int ATTEMPT_WINDOW_MINUTES = 10;
    private static final int LOCK_DURATION_MINUTES = 10;

    // Cache for failed attempts: key = "email:action", value = AttemptRecord
    private final Cache<String, AttemptRecord> attemptCache;

    // Cache for locked accounts: key = "email:action", value = lockUntil timestamp
    private final Cache<String, Instant> lockCache;

    public AntiBruteForceService() {
        this.attemptCache = Caffeine.newBuilder()
                .expireAfterWrite(ATTEMPT_WINDOW_MINUTES, TimeUnit.MINUTES)
                .build();

        this.lockCache = Caffeine.newBuilder()
                .expireAfterWrite(LOCK_DURATION_MINUTES, TimeUnit.MINUTES)
                .build();
    }

    /**
     * Check if account is locked for specific action
     * @throws AccountLockedException if account is locked
     */
    public void checkIfLocked(String email, String action) {
        String key = buildKey(email, action);
        Instant lockUntil = lockCache.getIfPresent(key);

        if (lockUntil != null && Instant.now().isBefore(lockUntil)) {
            long minutesRemaining = Duration.between(Instant.now(), lockUntil).toMinutes() + 1;
            log.warn("Account locked - Email: {}, Action: {}, Minutes remaining: {}", email, action, minutesRemaining);
            throw new AccountLockedException(
                    String.format("Tai khoan tam thoi bi khoa do nhap sai qua nhieu lan. Vui long thu lai sau %d phut nua.", minutesRemaining)
            );
        }

        // If lock expired, clean up
        if (lockUntil != null) {
            lockCache.invalidate(key);
            attemptCache.invalidate(key);
        }
    }

    /**
     * Record a failed attempt
     * Locks account if max attempts exceeded
     */
    public void recordFailedAttempt(String email, String action) {
        String key = buildKey(email, action);
        AttemptRecord record = attemptCache.getIfPresent(key);

        if (record == null) {
            record = new AttemptRecord(1, Instant.now());
        } else {
            record = new AttemptRecord(record.count + 1, record.firstAttempt);
        }

        attemptCache.put(key, record);

        log.debug("Failed attempt recorded - Email: {}, Action: {}, Count: {}", email, action, record.count);

        // Lock account if max attempts exceeded
        if (record.count >= MAX_ATTEMPTS) {
            Instant lockUntil = Instant.now().plus(Duration.ofMinutes(LOCK_DURATION_MINUTES));
            lockCache.put(key, lockUntil);
            attemptCache.invalidate(key);
            log.warn("Account locked - Email: {}, Action: {}, Lock until: {}", email, action, lockUntil);
        }
    }

    /**
     * Reset attempts on successful authentication
     */
    public void resetAttempts(String email, String action) {
        String key = buildKey(email, action);
        attemptCache.invalidate(key);
        lockCache.invalidate(key);
        log.debug("Attempts reset - Email: {}, Action: {}", email, action);
    }

    /**
     * Get remaining attempts before lock
     */
    public int getRemainingAttempts(String email, String action) {
        String key = buildKey(email, action);
        AttemptRecord record = attemptCache.getIfPresent(key);
        return record == null ? MAX_ATTEMPTS : Math.max(0, MAX_ATTEMPTS - record.count);
    }

    private String buildKey(String email, String action) {
        return email.toLowerCase() + ":" + action;
    }

    /**
     * Internal record to track attempts
     */
    private record AttemptRecord(int count, Instant firstAttempt) {}
}
