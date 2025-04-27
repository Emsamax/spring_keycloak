package org.springframework.samples.petclinic.system;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


@Configuration
//@EnableWebSecurity
public class SecurityConfiguration {


	private static final String[] INTERNAL_RESOURCES = {
		"/leaflet/**", "/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico"
	};

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers(INTERNAL_RESOURCES).permitAll()
				.anyRequest().authenticated()
			)
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfo -> userInfo
					.oidcUserService(oidcUserService())
				)
			)
			.logout(logout -> logout
				.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()) // Optionnel, peut rediriger sans vue
				.logoutSuccessUrl("/") // Ou redirection vers page d'accueil
				.invalidateHttpSession(true)
				.clearAuthentication(true)
				.deleteCookies("JSESSIONID", "SESSION", "XSRF-TOKEN") // Suppression complète
			)
			.sessionManagement(session -> session
				.maximumSessions(1)
				.maxSessionsPreventsLogin(false)
			);

		return http.build();
	}

	@Bean
	public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcUserService delegate = new OidcUserService();

		return userRequest -> {
			OidcUser oidcUser = delegate.loadUser(userRequest);

			Map<String, Object> claims = oidcUser.getClaims();
			List<String> roles = ((Map<String, List<String>>) claims.getOrDefault("realm_access", Map.of()))
				.getOrDefault("roles", List.of());

			Set<SimpleGrantedAuthority> authorities = roles.stream()
				.map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
				.collect(Collectors.toSet());

			return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
		};
	}
}

