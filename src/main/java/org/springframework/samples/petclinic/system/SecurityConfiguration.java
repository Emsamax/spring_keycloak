package org.springframework.samples.petclinic.system;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.security.servlet.StaticResourceRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	private static final String REALM_ACCESS = "realm_access";
	private static final String ROLES = "roles";
	private static final String[] RESTRICTED_RESOURCES = {"/owners/*"};
	private static final String AUTHORITY_ADM = "adm";
	private static final String[] INTERNAL_RESOURCES = {
		"/leaflet/**", "/css/**", "/fonts/**", "/images/**", "/static/**", "/login", "/oauth2/**", "/webjars/**"};

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers(INTERNAL_RESOURCES).permitAll()
				.requestMatchers(RESTRICTED_RESOURCES).hasAuthority(AUTHORITY_ADM)
				.anyRequest().authenticated()
			)
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService()))
				.defaultSuccessUrl("/", true)
			)
			.logout(logout -> logout
				.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()) // Optionnel, peut rediriger sans vue
				.logoutSuccessUrl("/login") // Ou redirection vers page d'accueil
				.invalidateHttpSession(true)
				.clearAuthentication(true)
				.deleteCookies("JSESSIONID")
			);
		http.csrf(AbstractHttpConfigurer::disable);
		return http.build();
	}


	@Bean
	public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		return userRequest -> {
			var user = new OidcUserService().loadUser(userRequest);
			var claims = user.getClaims();
			if (!claims.isEmpty()) {
				var realmAccess = (Map<String, Object>) claims.get(REALM_ACCESS);
				if (realmAccess != null && realmAccess.containsKey(ROLES)) {
					var realmRoles = realmAccess.get(ROLES);
					if (realmRoles instanceof Collection<?> && !((Collection<?>) realmRoles).isEmpty()) {
						var authorities = ((Collection<?>) realmRoles).stream()
							.map(role -> new SimpleGrantedAuthority((String) role))
							.collect(Collectors.toList());
						return new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo());
					} else {
						throw new OAuth2AuthenticationException("No realm_roles found");
					}
				} else {
					throw new OAuth2AuthenticationException("No realm_access found");
				}
			} else {
				throw new OAuth2AuthenticationException("Claims cannot be empty");
			}
		};
	}
}



