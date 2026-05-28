package com.logistics.authentication.infrastructure.adapter.in.web;

import java.util.List;

import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.Link;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.logistics.authentication.application.port.in.LoginUseCase;
import com.logistics.authentication.application.port.in.LoginUseCase.LoginCommand;
import com.logistics.authentication.application.port.in.LoginUseCase.LoginResult;
import com.logistics.authentication.application.port.in.RefreshTokenUseCase;
import com.logistics.authentication.application.port.in.RefreshTokenUseCase.RefreshCommand;
import com.logistics.authentication.application.port.in.RegisterUseCase;
import com.logistics.authentication.application.port.in.RegisterUseCase.RegisterCommand;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.LoginRequest;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.LoginResponseBody;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.MeResponseBody;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.RefreshRequest;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.RegisterRequest;
import com.logistics.authentication.infrastructure.adapter.in.web.dto.RegisterResponseBody;
import com.logistics.authentication.infrastructure.adapter.in.web.security.JwtPrincipal;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Autenticación", description = "Login con JWT (RBAC en claims)")
public class AuthController {

	private final LoginUseCase loginUseCase;
	private final RefreshTokenUseCase refreshTokenUseCase;
	private final RegisterUseCase registerUseCase;

	@Operation(
			summary = "Registro de usuario",
			description = "Crea solicitud con rol OPERATOR; requiere aprobación de un administrador.")
	@PostMapping(
			value = "/register",
			produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" },
			consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<EntityModel<RegisterResponseBody>> register(@Valid @RequestBody RegisterRequest request) {
		var result = registerUseCase.register(new RegisterCommand(request.email(), request.password()));
		var body = new RegisterResponseBody(result.userId(), result.email(), result.status(), result.message());
		return ResponseEntity.status(HttpStatus.CREATED).body(EntityModel.of(body));
	}

	@Operation(summary = "Login", description = "Autentica por correo y contraseña; devuelve JWT Bearer.")
	@PostMapping(
			value = "/login",
			produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" },
			consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<EntityModel<LoginResponseBody>> login(
			@Valid @RequestBody LoginRequest request,
			HttpServletRequest httpRequest) {
		var result = loginUseCase.login(new LoginCommand(request.email(), request.password()));
		return ResponseEntity.ok(toLoginModel(result, httpRequest));
	}

	@Operation(
			summary = "Renovar access token",
			description = "Envía el refresh token opaco; devuelve nuevos access + refresh (rotación).")
	@PostMapping(
			value = "/refresh",
			produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" },
			consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<EntityModel<LoginResponseBody>> refresh(
			@Valid @RequestBody RefreshRequest request,
			HttpServletRequest httpRequest) {
		var result = refreshTokenUseCase.refresh(new RefreshCommand(request.refreshToken()));
		return ResponseEntity.ok(toLoginModel(result, httpRequest));
	}

	private EntityModel<LoginResponseBody> toLoginModel(LoginResult result, HttpServletRequest request) {
		var body = new LoginResponseBody(
				result.accessToken(),
				result.tokenType(),
				result.expiresInSeconds(),
				result.roles(),
				result.refreshToken(),
				result.refreshExpiresInSeconds());
		EntityModel<LoginResponseBody> model = EntityModel.of(body);
		model.add(buildLink(request, "/swagger-ui/index.html", "describedby"));
		model.add(buildLink(request, "/v3/api-docs", "openapi"));
		model.add(buildLink(request, "/api/v1/auth/refresh", "refresh"));
		return model;
	}

	@Operation(
			summary = "Perfil actual (JWT)",
			description = "Devuelve datos del token Bearer (RBAC).",
			security = @SecurityRequirement(name = "bearer-jwt"))
	@GetMapping(value = "/me", produces = { MediaType.APPLICATION_JSON_VALUE, "application/hal+json" })
	public ResponseEntity<EntityModel<MeResponseBody>> me(
			Authentication authentication,
			HttpServletRequest request) {
		if (authentication == null
				|| !(authentication.getPrincipal() instanceof JwtPrincipal(String userId, String email))) {
			return ResponseEntity.status(401).build();
		}
		List<String> roles = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.toList();
		var body = new MeResponseBody(userId, email, roles);
		EntityModel<MeResponseBody> model = EntityModel.of(body);
		model.add(buildLink(request, "/api/v1/auth/me", "self"));
		model.add(buildLink(request, "/swagger-ui/index.html", "describedby"));
		return ResponseEntity.ok(model);
	}

	private static Link buildLink(HttpServletRequest request, String path, String rel) {
		String href = ServletUriComponentsBuilder.fromRequestUri(request)
				.replacePath(path)
				.replaceQuery(null)
				.build()
				.toUriString();
		return Link.of(href, rel);
	}
}
