package co.medistock.security.adapters;
import co.medistock.security.core.Account;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.*;
import java.util.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
public final class JwtSupport {
    private final RSAKey key;
    private final JwtEncoder encoder;
    private final NimbusJwtDecoder decoder;
    public JwtSupport(RSAPublicKey publicKey, RSAPrivateKey privateKey, String kid) {
        if (!publicKey.getModulus().equals(privateKey.getModulus()) || kid == null || kid.isBlank()) throw new IllegalArgumentException("Invalid RSA key pair or identifier.");
        key=new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(kid).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
        encoder=new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
        decoder=NimbusJwtDecoder.withPublicKey(publicKey).signatureAlgorithm(SignatureAlgorithm.RS256).build();
        OAuth2TokenValidator<Jwt> claims=jwt -> {
            try {
                String subject=jwt.getSubject(); var roles=jwt.getClaimAsStringList("roles");
                boolean valid=subject!=null && UUID.fromString(subject).toString().equals(subject) && jwt.getExpiresAt()!=null
                    && jwt.getAudience().contains("mis-api") && roles!=null && !roles.isEmpty()
                    && List.of("ADMIN","INVENTORY","SUPERVISOR","CONSULTATION").containsAll(roles);
                if (valid) return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException ignored) { }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Invalid required claims.",null));
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(Duration.ofSeconds(30)),new JwtIssuerValidator("mis-security"),claims));
    }
    public String issue(Account account) {
        var now=Instant.now();
        var claims=JwtClaimsSet.builder().issuer("mis-security").subject(account.id().toString()).audience(List.of("mis-api"))
            .issuedAt(now).expiresAt(now.plusSeconds(3600)).claim("roles",account.roles()).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).keyId(key.getKeyID()).build(),claims)).getTokenValue();
    }
    public JwtDecoder decoder() { return decoder; }
    public Map<String,Object> jwks() { return Map.of("keys",List.of(key.toPublicJWK().toJSONObject())); }
}
