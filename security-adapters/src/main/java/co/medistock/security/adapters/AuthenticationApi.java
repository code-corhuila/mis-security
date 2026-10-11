package co.medistock.security.adapters;
import co.medistock.security.core.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
@RestController
public class AuthenticationApi {
    private final Authenticate authenticate;
    private final JwtSupport tokens;
    private final JdbcTemplate jdbc;
    public AuthenticationApi(Authenticate authenticate, JwtSupport tokens, JdbcTemplate jdbc) { this.authenticate=authenticate;this.tokens=tokens;this.jdbc=jdbc; }
    public record LoginRequest(@NotBlank @Size(max=80) String username,@NotEmpty @Size(max=72) String password) {}
    public record User(UUID id,String username,String displayName,List<String> roles) {
        static User from(Account a) { return new User(a.id(),a.username(),a.displayName(),a.roles()); }
    }
    public record LoginResponse(String accessToken,String tokenType,int expiresIn,User user) {}
    public static final class InvalidPasswordSize extends RuntimeException {}
    @PostMapping("/api/v1/auth/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        if (request.password().getBytes(StandardCharsets.UTF_8).length>72) throw new InvalidPasswordSize();
        var account=authenticate.login(request.username(),request.password());
        return new LoginResponse(tokens.issue(account),"Bearer",3600,User.from(account));
    }
    @GetMapping("/api/v1/auth/me")
    public User current(@AuthenticationPrincipal Jwt jwt) { return User.from(authenticate.current(UUID.fromString(jwt.getSubject()))); }
    @GetMapping("/api/v1/auth/jwks")
    public Map<String,Object> keys() { return tokens.jwks(); }
    @GetMapping("/health")
    public Map<String,String> health() { jdbc.queryForObject("SELECT 1",Integer.class);return Map.of("status","UP"); }
}
