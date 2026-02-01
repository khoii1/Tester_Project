package com.noel.springsecurity.filters;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import com.noel.springsecurity.exceptions.RateLimitExceededException;
import com.noel.springsecurity.services.RateLimitingService;

import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitingService rateLimitingService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Only apply to Auth endpoints
        if (request.getRequestURI().startsWith("/api/v1/auth")) {
            // Identify the Client (IP Address + Endpoint)
            String clientIp = getClientIp(request);
            String endpoint = request.getRequestURI();
            String bucketKey = clientIp + ":" + endpoint;
            
            log.debug("Rate limiting check - IP: {}, Endpoint: {}", clientIp, endpoint);
            
            // Get their bucket
            Bucket bucket = rateLimitingService.resolveBucket(bucketKey);
            // Try to consume 1 token
            if (bucket.tryConsume(1)) {
                // Success: Proceed
                log.debug("Rate limit OK - Tokens remaining: {}", bucket.getAvailableTokens());
                filterChain.doFilter(request, response);
            } else {
                // Failure: Throw Exception (caught by GlobalExceptionHandler)
                log.warn("Rate limit exceeded - IP: {}, Endpoint: {}", clientIp, endpoint);
                handlerExceptionResolver.resolveException(request, response, null,
                        new RateLimitExceededException("Qua nhieu yeu cau. Vui long thu lai sau."));
            }
        } else {
            // Not an auth route? Just continue.
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Extracts the real IP address, handling proxies/load balancers.
     */
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        // X-Forwarded-For: client, proxy1, proxy2
        return xfHeader.split(",")[0];
    }
}