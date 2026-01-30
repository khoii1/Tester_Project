package com.noel.springsecurity.config;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.mail.javamail.JavaMailSender;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;

/**
 * Test configuration to mock email service
 * Prevents actual emails from being sent during tests
 */
@TestConfiguration
public class TestEmailConfig {

    @Bean
    @Primary
    public JavaMailSender javaMailSender() {
        JavaMailSender mailSender = mock(JavaMailSender.class);
        
        // Create a mock MimeMessage
        MimeMessage mimeMessage = new MimeMessage((Session) null);
        
        // Configure the mock to return the MimeMessage when createMimeMessage() is called
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        
        // Do nothing when send is called
        doNothing().when(mailSender).send(any(MimeMessage.class));
        
        return mailSender;
    }
}

