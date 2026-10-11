package co.medistock.security.app;
import co.medistock.security.adapters.*;
import java.util.Set;
import org.springframework.context.annotation.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.*;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
@EnableMethodSecurity
public class WebSecurity {
    @Bean SecurityFilterChain security(HttpSecurity http,JwtSupport tokens,Errors errors) throws Exception {
        var roles=new JwtGrantedAuthoritiesConverter();roles.setAuthoritiesClaimName("roles");roles.setAuthorityPrefix("ROLE_");
        var converter=new JwtAuthenticationConverter();converter.setJwtGrantedAuthoritiesConverter(roles);
        var publicPaths=Set.of("/health","/api/v1/auth/login","/api/v1/auth/jwks");
        var resolver=new DefaultBearerTokenResolver();
        http.csrf(csrf->csrf.disable()).sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth->auth.requestMatchers("/api/v1/auth/me").authenticated().anyRequest().permitAll())
            .oauth2ResourceServer(resource->resource.bearerTokenResolver(request->publicPaths.contains(request.getRequestURI())?null:resolver.resolve(request))
                .jwt(jwt->jwt.decoder(tokens.decoder()).jwtAuthenticationConverter(converter))
                .authenticationEntryPoint((request,response,error)->errors.write(request,response,401,"UNAUTHORIZED","Autenticacion requerida.",null)))
            .exceptionHandling(handler->handler.authenticationEntryPoint((request,response,error)->errors.write(request,response,401,"UNAUTHORIZED","Autenticacion requerida.",null))
                .accessDeniedHandler((request,response,error)->errors.write(request,response,403,"FORBIDDEN","Permisos insuficientes.",null)));
        return http.build();
    }
}
