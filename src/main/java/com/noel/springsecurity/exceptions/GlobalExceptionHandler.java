package com.noel.springsecurity.exceptions;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.noel.springsecurity.dto.response.ApiErrorResponse;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    // Helper method to build response
    private ResponseEntity<ApiErrorResponse> buildResponse(HttpStatus status, String message) {
        return new ResponseEntity<>(ApiErrorResponse.builder()
                .statusCode(status.value())
                .errorReason(status.getReasonPhrase())
                .message(message)
                .build(), status);
    }

    // Handle Validation Errors (@Valid annotations)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidationErrors(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        ApiErrorResponse response = ApiErrorResponse.builder()
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .errorReason("Lỗi xác thực")
                .message(errors)
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // Handle Token Refresh Errors (403 Forbidden)
    @ExceptionHandler(TokenRefreshException.class)
    public ResponseEntity<ApiErrorResponse> handleTokenRefreshException(TokenRefreshException ex) {
        return buildResponse(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    // Handle Bad Credentials (Login fail)
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleBadCredentials(BadCredentialsException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    // Handle Disabled Account (Email not verified)
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ApiErrorResponse> handleDisabledAccount(DisabledException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Tài khoản đã bị vô hiệu hóa hoặc email chưa được xác thực. Vui lòng kiểm tra email của bạn.");
    }

    // Handle User Already Exists
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleUserExists(UserAlreadyExistsException ex) {
        return buildResponse(HttpStatus.CONFLICT, ex.getMessage());
    }

    // Handle Not Found
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleNotFound(ResourceNotFoundException ex) {
        return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    /**
     * Handling JWT Errors
     */
    // Handle Expired JWT (Crucial for Refresh Token flow)
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ApiErrorResponse> handleExpiredJwt(ExpiredJwtException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Phiên đăng nhập của bạn đã hết hạn. Vui lòng đăng nhập lại.");
    }

    // Handle Invalid Signature / Malformed Token (Security)
    @ExceptionHandler({SignatureException.class, io.jsonwebtoken.MalformedJwtException.class, io.jsonwebtoken.security.SecurityException.class})
    public ResponseEntity<ApiErrorResponse> handleInvalidJwt(Exception ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại.");
    }

    // Catch-all for other JWT errors
    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ApiErrorResponse> handleGenericJwt(JwtException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, "Có lỗi xảy ra với phiên đăng nhập. Vui lòng thử lại.");
    }

    // Handle Expired Verification link toke
    @ExceptionHandler(LinkExpiredException.class)
    public ResponseEntity<ApiErrorResponse> handleExpiredVerificationLink(LinkExpiredException ex) {
        return buildResponse(HttpStatus.GONE, ex.getMessage());
    }

    // Handle Rate Limiting (429 Too Many Requests)
    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ApiErrorResponse> handleRateLimitExceeded(RateLimitExceededException ex) {
        ApiErrorResponse response = ApiErrorResponse.builder()
                .statusCode(HttpStatus.TOO_MANY_REQUESTS.value())
                .errorReason(HttpStatus.TOO_MANY_REQUESTS.getReasonPhrase())
                .message(ex.getMessage())
                .build();
        
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("X-Rate-Limit-Retry-After-Seconds", "60")
                .body(response);
    }

    // Handle Account Locked (429 Too Many Requests)
    // Changed from 423 to 429 because anti-brute force is a type of rate limiting
    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccountLocked(AccountLockedException ex) {
        ApiErrorResponse response = ApiErrorResponse.builder()
                .statusCode(HttpStatus.TOO_MANY_REQUESTS.value())
                .errorReason(HttpStatus.TOO_MANY_REQUESTS.getReasonPhrase())
                .message(ex.getMessage())
                .build();
        
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("X-Rate-Limit-Retry-After-Seconds", String.valueOf(10 * 60)) // 10 minutes in seconds
                .body(response);
    }

    // Handle RBAC Access Denied
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDeniedException(AccessDeniedException ex) {
        return buildResponse(HttpStatus.FORBIDDEN, "Bạn không có quyền truy cập tài nguyên này. Vui lòng liên hệ quản trị viên.");
    }

    // Handle unsupported HTTP methods
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> requestMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return buildResponse(HttpStatus.METHOD_NOT_ALLOWED, "Phương thức yêu cầu không được hỗ trợ.");
    }


    // Fallback for everything else
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleGlobalException(Exception ex) {
        log.error("Unhandled exception: {}", ex.getMessage());
        ex.printStackTrace();
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Đã xảy ra lỗi không mong muốn. Vui lòng thử lại sau.");
    }
}