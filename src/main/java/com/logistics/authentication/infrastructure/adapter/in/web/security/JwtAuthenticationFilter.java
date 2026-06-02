package com.logistics.authentication.infrastructure.adapter.in.web.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;

import org.springframework.util.AntPathMatcher;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import org.slf4j.MDC;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.ApiErrorResponse;
import com.logistics.authentication.infrastructure.adapter.in.web.filter.TraceIdFilter;
import com.logistics.authentication.infrastructure.config.JwtProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Valida JWT Bearer y rellena el contexto de seguridad (RBAC por claims).
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final AntPathMatcher MATCHER = new AntPathMatcher();

	private static final Set<String> PUBLIC_PATH_PATTERNS = Set.of(
			"/api/v1/auth/login",
			"/api/v1/auth/register",
			"/api/v1/auth/refresh",
			"/v3/api-docs/**",
			"/swagger-ui/**",
			"/swagger-ui.html");

	private final JwtProperties jwtProperties;
	private final ObjectMapper objectMapper;

	/** No validar JWT en login ni documentación (evita 401 si se envía un Bearer erróneo en /login). */
	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String path = request.getServletPath();
		return PUBLIC_PATH_PATTERNS.stream().anyMatch(pattern -> MATCHER.match(pattern, path));
	}

	@Override
	protected void doFilterInternal(
			HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		String bearerToken = extractBearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));
		if (bearerToken == null) {
			filterChain.doFilter(request, response);
			return;
		}
		try {
			applyAuthenticationFromToken(bearerToken);
		}
		catch (JwtException | IllegalArgumentException ex) {
			writeUnauthorized(response, request);
			return;
		}
		filterChain.doFilter(request, response);
	}

	private static String extractBearerToken(String authorizationHeader) {
		if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
			return null;
		}
		return authorizationHeader.substring(7);
	}

	private void applyAuthenticationFromToken(String token) {
		SecretKey key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
		Claims claims = Jwts.parser()
				.verifyWith(key)
				.build()
				.parseSignedClaims(token)
				.getPayload();

		String userId = claims.getSubject();
		String email = claims.get("email", String.class);
		Collection<GrantedAuthority> authorities = toAuthorities(extractRoles(claims.get("roles")));
		Authentication auth = new UsernamePasswordAuthenticationToken(
				new JwtPrincipal(userId, email),
				null,
				authorities);
		SecurityContextHolder.getContext().setAuthentication(auth);
	}

	private static Collection<GrantedAuthority> toAuthorities(List<String> roles) {
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		for (String role : roles) {
			if (role != null && !role.isBlank()) {
				authorities.add(new SimpleGrantedAuthority(role.startsWith("ROLE_") ? role : "ROLE_" + role));
			}
		}
		return authorities;
	}

	private void writeUnauthorized(HttpServletResponse response, HttpServletRequest request) throws IOException {
		SecurityContextHolder.clearContext();
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		String trace = firstNonBlank(
				MDC.get(TraceIdFilter.TRACE_ID_MDC),
				request.getHeader(TraceIdFilter.TRACE_ID_HEADER));
		var body = new ApiErrorResponse(
				"INVALID_OR_EXPIRED_TOKEN",
				"Token Bearer inválido o expirado",
				null,
				trace);
		objectMapper.writeValue(response.getOutputStream(), body);
	}

	private static List<String> extractRoles(Object raw) {
		if (raw == null) {
			return List.of();
		}
		if (raw instanceof Collection<?> c) {
			List<String> out = new ArrayList<>();
			for (Object o : c) {
				if (o != null) {
					out.add(o.toString());
				}
			}
			return out;
		}
		return List.of(raw.toString());
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
