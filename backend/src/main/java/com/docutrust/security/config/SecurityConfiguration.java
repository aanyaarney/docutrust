package com.docutrust.security.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.docutrust.common.config.DocuTrustProperties;
import com.docutrust.security.api.JwtAuthenticationFilter;
import com.docutrust.security.api.RestAccessDeniedHandler;
import com.docutrust.security.api.RestAuthenticationEntryPoint;

/**
 * HTTP security configuration.
 *
 * <h2>Why CSRF protection is disabled here</h2>
 * CSRF attacks work because browsers attach ambient credentials — cookies —
 * to cross-site requests automatically. DocuTrust authenticates with a bearer
 * token in an {@code Authorization} header, which a browser never attaches on
 * its own; an attacking page would have to read the token first, and same-origin
 * policy prevents that. With no ambient credential there is no CSRF vector, so
 * token synchronisation would add machinery without adding protection.
 *
 * <p>This reasoning depends entirely on the token never being stored in a
 * cookie. If authentication ever moves to cookies, CSRF protection must be
 * switched back on in the same change.
 *
 * <h2>Session policy</h2>
 * Stateless. No server-side session is created, so there is no session to fixate
 * or hijack, and horizontal scaling needs no session replication.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

    private final DocuTrustProperties properties;

    public SecurityConfiguration(DocuTrustProperties properties) {
        this.properties = properties;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtFilter,
            RestAuthenticationEntryPoint authenticationEntryPoint,
            RestAccessDeniedHandler accessDeniedHandler) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // See class javadoc: bearer tokens, not cookies.

            // 401 for "not authenticated", 403 for "authenticated but not
            // permitted". Both are registered explicitly: the client acts on
            // the difference - 401 sends the user back to sign in, 403 must
            // not - so it is too important to leave to framework defaults.
            .exceptionHandling(handling -> handling
                    .authenticationEntryPoint(authenticationEntryPoint)
                    .accessDeniedHandler(accessDeniedHandler))
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    // Pre-flight must not require authentication.
                    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                    // Authentication and health are necessarily open.
                    .requestMatchers("/api/v1/auth/login").permitAll()
                    .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                    // API documentation, useful in development.
                    .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()

                    // Metrics expose operational detail; administrators only.
                    .requestMatchers("/actuator/**").hasRole("ADMIN")

                    // System-wide audit and trust configuration.
                    .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")

                    .anyRequest().authenticated())

            .headers(headers -> headers
                    .contentTypeOptions(Customizer.withDefaults())
                    .frameOptions(frame -> frame.deny())
                    .httpStrictTransportSecurity(hsts -> hsts
                            .includeSubDomains(true)
                            .maxAgeInSeconds(31536000)))

            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * BCrypt at strength 12.
     *
     * <p>BCrypt is deliberately slow and salts every hash, which is what makes
     * offline cracking of a leaked password table expensive. Strength 12 costs
     * roughly a quarter second per hash on current hardware — negligible at
     * login, punishing at scale for an attacker.
     *
     * <p>DocuTrust implements no password hashing of its own.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Explicit origins only. Wildcards plus credentials is a combination
        // browsers reject, and permitting any origin would let any site call
        // the API with a user's token.
        configuration.setAllowedOrigins(properties.getCors().getAllowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Correlation-Id"));
        configuration.setExposedHeaders(List.of("Content-Disposition", "X-Correlation-Id"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }
}
