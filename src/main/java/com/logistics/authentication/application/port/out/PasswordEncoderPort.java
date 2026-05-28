package com.logistics.authentication.application.port.out;

public interface PasswordEncoderPort {

	boolean matches(String rawPassword, String encodedPassword);

	String encode(String rawPassword);
}