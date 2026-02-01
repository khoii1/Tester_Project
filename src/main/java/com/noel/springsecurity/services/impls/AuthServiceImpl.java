package com.noel.springsecurity.services.impls;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.RegisterRequest;
import com.noel.springsecurity.entities.EmailVerification;
import com.noel.springsecurity.entities.RefreshToken;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.ERole;
import com.noel.springsecurity.events.PasswordResetEvent;
import com.noel.springsecurity.events.SendOtpEvent;
import com.noel.springsecurity.exceptions.LinkExpiredException;
import com.noel.springsecurity.exceptions.ResourceNotFoundException;
import com.noel.springsecurity.exceptions.TokenRefreshException;
import com.noel.springsecurity.exceptions.UserAlreadyExistsException;
import com.noel.springsecurity.mappers.IUserMapper;
import com.noel.springsecurity.repositories.IEmailVerificationRepository;
import com.noel.springsecurity.repositories.IUserRepository;
import com.noel.springsecurity.security.UserPrincipal;
import com.noel.springsecurity.security.jwt.JwtService;
import com.noel.springsecurity.services.AntiBruteForceService;
import com.noel.springsecurity.services.IAuthService;
import com.noel.springsecurity.services.IRefreshTokenService;
import com.noel.springsecurity.utils.TokenHashUtil;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {
    private final IUserRepository userRepository;
    private final IEmailVerificationRepository emailVerificationRepository;
    private final IRefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final ApplicationEventPublisher eventPublisher;
    private final IUserMapper userMapper;
    private final AntiBruteForceService antiBruteForceService;
    @Value("${app.security.email.reset-password-expiration}")
    private int resetPasswordExpirationMinutes;
    @Value("${app.security.email.reset-password-url}")
    private String passwordResetLink;

    // SEND OTP
    @Override
    @Transactional
    public void sendRegistrationOtp(String email) {
        // Check if account is locked for OTP sending
        antiBruteForceService.checkIfLocked(email, "send-otp");

        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("Email này đã được đăng ký. Vui lòng đăng nhập.");
        }
        // Generate Secure OTP
        String otp = String.format("%06d", new SecureRandom().nextInt(999999));
        // Save OTP in the database
        EmailVerification verification = new EmailVerification(
                email,
                otp,
                LocalDateTime.now().plusMinutes(10) // Valid for 10 mins
        );
        emailVerificationRepository.save(verification);

        // Publish Async Event (Sends Email)
        eventPublisher.publishEvent(new SendOtpEvent(email, otp));
    }

    // VERIFY OTP
    @Override
    @Transactional
    public String verifyOtp(String email, String otp) {
        // Check if account is locked for OTP verification
        antiBruteForceService.checkIfLocked(email, "verify-otp");

        EmailVerification verification = emailVerificationRepository.findByEmail(email)
                .orElse(null);
        
        // Record failed attempt even when OTP not found (anti-brute force protection)
        if (verification == null || verification.getExpiryDate().isBefore(LocalDateTime.now()) 
                || !verification.getOtpCode().equals(otp)) {
            antiBruteForceService.recordFailedAttempt(email, "verify-otp");
            
            if (verification == null) {
                throw new ResourceNotFoundException("Email không hợp lệ hoặc chưa gửi mã OTP.");
            }
            if (verification.getExpiryDate().isBefore(LocalDateTime.now())) {
                throw new LinkExpiredException("Mã OTP đã hết hạn. Vui lòng yêu cầu mã mới.");
            }
            throw new BadCredentialsException("Mã OTP không chính xác. Vui lòng kiểm tra lại.");
        }
        
        // Cleanup (One-time use)
        emailVerificationRepository.delete(verification);
        // Reset attempts on success
        antiBruteForceService.resetAttempts(email, "verify-otp");
        // Issue "Pre-Auth" Token
        return jwtService.generateRegistrationToken(email);
    }

    // REGISTER (Finalize)
    @Override
    @Transactional
    public AuthResult register(RegisterRequest request, String preAuthToken) {
        if (jwtService.isTokenExpired(preAuthToken) || !jwtService.isRegistrationToken(preAuthToken)) {
            throw new BadCredentialsException("Phiên đăng ký không hợp lệ hoặc đã hết hạn. Vui lòng thử lại.");
        }
        String email = jwtService.extractUserSubject(preAuthToken);
        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("Email này đã được sử dụng.");
        }
        // Create User
        User user = new User();
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(ERole.USER);
        user.setEnabled(true);

        User savedUser = userRepository.save(user);
        String accessToken = jwtService.generateAccessToken(savedUser);
        String refreshToken = refreshTokenService.createRefreshToken(savedUser);

        return new AuthResult(accessToken, refreshToken, userMapper.toDto(savedUser));
    }

    // STANDARD LOGIN
    @Override
    @Transactional
    public AuthResult login(LoginRequest request) {
        // Check if account is locked for login
        antiBruteForceService.checkIfLocked(request.email(), "login");

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );
        } catch (BadCredentialsException e) {
            // Record failed attempt
            antiBruteForceService.recordFailedAttempt(request.email(), "login");
            throw new BadCredentialsException("Email hoặc mật khẩu không chính xác. Vui lòng thử lại.");
        } catch (DisabledException e) {
            throw new DisabledException("Tài khoản của bạn đã bị vô hiệu hóa. Vui lòng liên hệ quản trị viên.");
        }
        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        User user = principal.getUser();
        // Reset attempts on successful login
        antiBruteForceService.resetAttempts(request.email(), "login");
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user);

        return new AuthResult(accessToken, refreshToken, userMapper.toDto(user));
    }

    // REFRESH TOKEN
    @Override
    @Transactional
    public AuthResult refreshToken(String incomingRefreshToken) {
        RefreshToken existingToken = refreshTokenService.findByToken(incomingRefreshToken)
                .orElseThrow(() -> new TokenRefreshException("Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại."));
        refreshTokenService.verifyExpiration(existingToken);
        User user = existingToken.getUser();
        if (!user.isEnabled()) {
            throw new TokenRefreshException("Tài khoản của bạn đã bị vô hiệu hóa.");
        }
        // Rotate Token - delete old, create new
        refreshTokenService.delete(existingToken);
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = refreshTokenService.createRefreshToken(user);

        return new AuthResult(newAccessToken, newRefreshToken, userMapper.toDto(user));
    }

    // LOGOUT
    @Override
    @Transactional
    public void logout(String incomingRefreshToken) {
        if (incomingRefreshToken == null) return;
        refreshTokenService.deleteByToken(incomingRefreshToken);
        SecurityContextHolder.clearContext();
    }

    // PASSWORD RESET REQUEST
    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        // Check if account is locked for password reset
        antiBruteForceService.checkIfLocked(email, "reset-password");

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    // Record failed attempt when email not found
                    antiBruteForceService.recordFailedAttempt(email, "reset-password");
                    return new ResourceNotFoundException("Email không tồn tại trong hệ thống. Vui lòng kiểm tra lại.");
                });

        String rawToken = UUID.randomUUID().toString();
        String hashedToken = TokenHashUtil.hashToken(rawToken);
        user.setPasswordResetToken(hashedToken);
        user.setPasswordResetTokenExpiry(
                LocalDateTime.now().plusMinutes(resetPasswordExpirationMinutes)
        );
        userRepository.save(user);

        String fullName = user.getFirstName() + " " + user.getLastName();
        String link = passwordResetLink + "?token=" + rawToken;
        // Publish Async Event
        eventPublisher.publishEvent(new PasswordResetEvent(user.getEmail(), fullName, link));
    }

    // RESET PASSWORD
    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        String hashedToken = TokenHashUtil.hashToken(token);
        User user = userRepository.findByPasswordResetToken(hashedToken)
                .orElse(null);
        
        // For reset-password, track globally per action to prevent brute force
        // This prevents attackers from trying multiple different tokens
        String trackingKey = "reset-password-global";
        
        // Check if locked
        antiBruteForceService.checkIfLocked(trackingKey, "reset-password");
        
        // Record failed attempt even when token invalid (anti-brute force protection)
        if (user == null || user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            antiBruteForceService.recordFailedAttempt(trackingKey, "reset-password");
            
            if (user == null) {
                throw new ResourceNotFoundException("Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.");
            }
            throw new LinkExpiredException("Liên kết đặt lại mật khẩu đã hết hạn. Vui lòng yêu cầu liên kết mới.");
        }
        
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        userRepository.save(user);
        // Reset attempts on successful password reset
        antiBruteForceService.resetAttempts(trackingKey, "reset-password");
        // Security: Revoke all sessions to force re-login with a new password
        refreshTokenService.deleteByUser(user);
    }
}