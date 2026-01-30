package com.noel.springsecurity.utils;

import com.noel.springsecurity.dto.request.LoginRequest;
import com.noel.springsecurity.dto.request.RegisterRequest;
import com.noel.springsecurity.dto.request.OtpRequest;
import com.noel.springsecurity.dto.request.VerifyOtpRequest;
import com.noel.springsecurity.entities.User;
import com.noel.springsecurity.enums.ERole;

/**
 * Helper class to create test data
 */
public class TestDataBuilder {

    public static User createTestUser(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(password);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setRole(ERole.USER);
        user.setEnabled(true);
        return user;
    }

    public static LoginRequest createLoginRequest(String email, String password) {
        return new LoginRequest(email, password);
    }

    public static RegisterRequest createRegisterRequest(String firstName, String lastName, String password) {
        return new RegisterRequest(firstName, lastName, password);
    }

    public static OtpRequest createOtpRequest(String email) {
        return new OtpRequest(email);
    }

    public static VerifyOtpRequest createVerifyOtpRequest(String email, String otp) {
        return new VerifyOtpRequest(email, otp);
    }
}
