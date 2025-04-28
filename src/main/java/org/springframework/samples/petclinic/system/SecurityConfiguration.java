package org.springframework.samples.petclinic.system;

import org.springframework.boot.autoconfigure.security.servlet.StaticResourceRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

import java.util.*;
import java.util.stream.Collectors;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	private static final String REALM_ACCESS = "realm_access";


	private static final String[] INTERNAL_RESOURCES = {
		"/leaflet/**", "/css/**", "/fonts/**", "/images/**", "/static/**",
		"/", "/login", "/oauth2/**", "/webjars/**"
	};

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers(INTERNAL_RESOURCES).permitAll()
				.anyRequest().authenticated()
			)
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService()))
				.defaultSuccessUrl("/", true)
			)
			.logout(logout -> logout
				.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()) // Optionnel, peut rediriger sans vue
				.logoutSuccessUrl("/") // Ou redirection vers page d'accueil
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
			System.out.println("=================== ID Token =================== : " + user.getIdToken().getClaims());
			System.out.println("=================== User Info =================== : " + user.getUserInfo().getClaims());
			var claims = user.getClaims();
			if (!claims.isEmpty()) {
				var realmRoles = claims.get(REALM_ACCESS);
				if (realmRoles instanceof Collection<?> && !((Collection<?>) realmRoles).isEmpty()) {
					var authorities = ((Collection<?>) realmRoles).stream()
						.map(role -> new SimpleGrantedAuthority((String) role))
						.collect(Collectors.toList());
					return new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo());
				} else {
					throw new OAuth2AuthenticationException("No realm_roles found");
				}
			} else {
				throw new OAuth2AuthenticationException("Claims cannot be empty");
			}
		};
	}
}

