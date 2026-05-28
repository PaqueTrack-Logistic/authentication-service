package com.logistics.authentication.infrastructure.adapter.out.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.logistics.authentication.application.port.out.PasswordEncoderPort;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class PasswordEncoderAdapter implements PasswordEncoderPort {

	private final PasswordEncoder delegate;

	@Override
	public boolean matches(String rawPassword, String encodedPassword) {
		return delegate.matches(rawPassword, encodedPassword);
	}

	@Override
	public String encode(String rawPassword) {
		return delegate.encode(rawPassword);
	}
}
