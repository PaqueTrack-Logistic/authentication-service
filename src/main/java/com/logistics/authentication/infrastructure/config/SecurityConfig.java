package com.logistics.authentication.infrastructure.config;

import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApiErrorResponse;
import com.logistics.authentication.infrastructure.adapter.in.web.filter.TraceIdFilter;
import com.logistics.authentication.infrastructure.adapter.in.web.security.JwtAuthenticationFilter;
import com.logistics.authentication.infrastructure.adapter.in.web.security.JsonAuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final ObjectMapper objectMapper;
	private final JsonAuthenticationEntryPoint jsonAuthenticationEntryPoint;
	private final SecurityProperties securityProperties;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) {
		http
                // CSRF disabled because this is a stateless REST API using JWT authentication.
                // No session or cookies are used, so CSRF protection is not required.
				.csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.headers(this::securityHeaders)
				.exceptionHandling(e -> e
						.authenticationEntryPoint(jsonAuthenticationEntryPoint)
						.accessDeniedHandler((request, response, accessDeniedException) -> {
							response.setStatus(HttpServletResponse.SC_FORBIDDEN);
							response.setContentType(MediaType.APPLICATION_JSON_VALUE);
							String trace = firstNonBlank(
									MDC.get(TraceIdFilter.TRACE_ID_MDC),
									request.getHeader(TraceIdFilter.TRACE_ID_HEADER));
							var body = new ApiErrorResponse(
									"ACCESS_DENIED",
									"Permisos insuficientes para este recurso",
									null,
									trace);
							objectMapper.writeValue(response.getOutputStream(), body);
						}))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.requestMatchers("/api/v1/auth/login", "/api/v1/auth/refresh").permitAll()
						.requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
						.requestMatchers("/error").permitAll()
						.requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
						.anyRequest().authenticated())
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}

	private void securityHeaders(HeadersConfigurer<HttpSecurity> headers) {
		headers.frameOptions(frame -> frame.deny());
		headers.contentTypeOptions(Customizer.withDefaults());
		headers.referrerPolicy(referrer -> referrer.policy(
				ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN));
		if (securityProperties.isHstsEnabled()) {
			headers.httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000).includeSubDomains(true));
		}
	}

	private static String firstNonBlank(String a, String b) {
		if (a != null && !a.isBlank()) {
			return a;
		}
		if (b != null && !b.isBlank()) {
			return b;
		}
		return null;
	}

}
