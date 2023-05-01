package com.example.security.config;

import com.example.security.respository.InMemoryOAuth2AuthorizationRequestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author MoLi
 */
@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

//    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final String[] allowGetAnonymousRequestList = new String[]{
            "/captcha",
            "/register"
    };
    private final String[] getAllowGetPermitAllRequestList = new String[]{
            "/v3/api-docs",
            "/v3/api-docs/v1",
            "/v3/api-docs/swagger-config",
            "/swagger-resources",
            "/swagger-ui/**",
            "/doc.html",
            "/webjars/**",
            "/*/favicon.ico",
            "/tag",
            "/content",
            "/classify",
            "/menu/tree",
            "/content/**",
            "/userInfo",
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests((authorize) -> authorize.requestMatchers(HttpMethod.GET, allowGetAnonymousRequestList).anonymous()
                        .requestMatchers(HttpMethod.GET, getAllowGetPermitAllRequestList).permitAll()
                        .requestMatchers(HttpMethod.POST, "/login").anonymous()
                        .requestMatchers(HttpMethod.POST, "check").anonymous()
                        .requestMatchers(new AntPathRequestMatcher("/check")).permitAll()
//                        .requestMatchers(new AntPathRequestMatcher("/oauth/**")).permitAll()
//                        .requestMatchers("/oauth/**").permitAll()
//                        .requestMatchers("/logout").authenticated()
//                        .requestMatchers("/admin/**").authenticated()
                        .anyRequest()
                        .authenticated())
//                .authorizeHttpRequests()
//                .requestMatchers(HttpMethod.GET, allowGetAnonymousRequestList).anonymous()
//                .requestMatchers(HttpMethod.GET, getAllowGetPermitAllRequestList).permitAll()
//                .requestMatchers(HttpMethod.POST, "/login").anonymous()
//                .requestMatchers(HttpMethod.POST, "check").anonymous()
//                .requestMatchers(HttpMethod.GET, "/oauth/**").permitAll()
//                .requestMatchers("/logout").authenticated()
//                .requestMatchers("/admin/**").authenticated()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .cors(withDefaults())
                .oauth2Client(oauth2 -> oauth2
                        .authorizationCodeGrant(codeGrant -> codeGrant
                                .authorizationRequestRepository(this.authorizationRequestRepository())
                        )
                )
                .oauth2Login(builder -> builder.authorizationEndpoint().authorizationRequestRepository(this.authorizationRequestRepository()))
                .build();
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new InMemoryOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOriginPatterns(Collections.singletonList("*"));
        corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
        corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
        return urlBasedCorsConfigurationSource;
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
