package co.medistock.security.adapters;
import co.medistock.security.core.Account;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import java.security.*;
import java.security.interfaces.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import org.springframework.security.oauth2.jwt.JwtException;
class JwtSupportTest {
    private static KeyPair pair;
    private JwtSupport support;
    @BeforeAll static void keys() throws Exception { var g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);pair=g.generateKeyPair(); }
    @BeforeEach void setup() { support=new JwtSupport((RSAPublicKey)pair.getPublic(),(RSAPrivateKey)pair.getPrivate(),"test-key"); }
    private String token(String issuer,String audience,String subject,List<String> roles,Date expiry,RSAPrivateKey key) throws Exception {
        var claims=new JWTClaimsSet.Builder().issuer(issuer).audience(audience).subject(subject).issueTime(new Date()).expirationTime(expiry).claim("roles",roles).build();
        var jwt=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key").build(),claims);jwt.sign(new RSASSASigner(key));return jwt.serialize();
    }
    @Test void issuesEachAllowedRole() {
        for (String role:List.of("ADMIN","INVENTORY","SUPERVISOR","CONSULTATION")) {
            var account=new Account(UUID.randomUUID(),"demo","Demo","hash",true,List.of(role));
            var jwt=support.decoder().decode(support.issue(account));assertEquals(account.id().toString(),jwt.getSubject());
            assertEquals(List.of(role),jwt.getClaimAsStringList("roles"));assertEquals(3600,jwt.getExpiresAt().getEpochSecond()-jwt.getIssuedAt().getEpochSecond());
        }
    }
    @Test void rejectsInvalidClaimsAndExpiry() throws Exception {
        var future=Date.from(Instant.now().plusSeconds(300));var id=UUID.randomUUID().toString();var key=(RSAPrivateKey)pair.getPrivate();
        for (String bad:List.of(token("other","mis-api",id,List.of("ADMIN"),future,key),token("mis-security","other",id,List.of("ADMIN"),future,key),token("mis-security","mis-api","invalid",List.of("ADMIN"),future,key),token("mis-security","mis-api",id,List.of("UNKNOWN"),future,key),token("mis-security","mis-api",id,List.of("ADMIN"),null,key),token("mis-security","mis-api",id,List.of("ADMIN"),Date.from(Instant.now().minusSeconds(120)),key)))
            assertThrows(JwtException.class,()->support.decoder().decode(bad));
    }
    @Test void rejectsDifferentSignature() throws Exception {
        var g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);
        var bad=token("mis-security","mis-api",UUID.randomUUID().toString(),List.of("ADMIN"),Date.from(Instant.now().plusSeconds(300)),(RSAPrivateKey)g.generateKeyPair().getPrivate());
        assertThrows(JwtException.class,()->support.decoder().decode(bad));
    }
    @Test void rejectsUnsignedAndHs256() throws Exception {
        var claims=new JWTClaimsSet.Builder().subject(UUID.randomUUID().toString()).expirationTime(Date.from(Instant.now().plusSeconds(300))).build();
        var jwt=new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),claims);jwt.sign(new MACSigner(new byte[32]));
        assertThrows(JwtException.class,()->support.decoder().decode(jwt.serialize()));assertThrows(JwtException.class,()->support.decoder().decode(new PlainJWT(claims).serialize()));
    }
    @Test void publishesOnlyPublicMaterial() {
        var key=(Map<?,?>)((List<?>)support.jwks().get("keys")).get(0);assertEquals(Set.of("kty","kid","use","alg","n","e"),key.keySet());
    }
}
