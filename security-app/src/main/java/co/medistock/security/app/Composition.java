package co.medistock.security.app;
import co.medistock.security.core.*;
import co.medistock.security.adapters.*;
import java.nio.file.*;
import java.security.KeyFactory;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
@Configuration
public class Composition {
    @Bean Errors errors() { return new Errors(); }
    @Bean FilterRegistrationBean<RequestContext> correlation(Errors errors) {
        var registration=new FilterRegistrationBean<>(new RequestContext(errors));registration.setOrder(Ordered.HIGHEST_PRECEDENCE);return registration;
    }
    @Bean BCryptPasswordEncoder passwords() { return new BCryptPasswordEncoder(12); }
    @Bean org.springframework.security.oauth2.jwt.JwtDecoder decoder(JwtSupport tokens) { return tokens.decoder(); }
    @Bean JdbcAccounts accounts(JdbcTemplate jdbc,PlatformTransactionManager manager) { return new JdbcAccounts(jdbc,new TransactionTemplate(manager)); }
    @Bean Authenticate authenticate(JdbcAccounts accounts,BCryptPasswordEncoder encoder) { return new Authenticate(accounts,encoder::matches,encoder.encode(UUID.randomUUID().toString())); }
    private byte[] pem(String path,String label) throws Exception {
        String value=Files.readString(Path.of(path)).replace("-----BEGIN "+label+"-----","").replace("-----END "+label+"-----","").replaceAll("\\s","");
        return Base64.getDecoder().decode(value);
    }
    @Bean JwtSupport tokens(@Value("${SECURITY_PUBLIC_KEY}") String publicPath,@Value("${SECURITY_PRIVATE_KEY}") String privatePath,@Value("${SECURITY_KEY_ID}") String kid) throws Exception {
        var factory=KeyFactory.getInstance("RSA");
        return new JwtSupport((RSAPublicKey)factory.generatePublic(new X509EncodedKeySpec(pem(publicPath,"PUBLIC KEY"))),(RSAPrivateKey)factory.generatePrivate(new PKCS8EncodedKeySpec(pem(privatePath,"PRIVATE KEY"))),kid);
    }
    @Bean ApplicationRunner bootstrap(JdbcAccounts accounts,BCryptPasswordEncoder passwords,Environment environment) {
        return args -> {
            String enabled=environment.getRequiredProperty("BOOTSTRAP_ENABLED");
            if (!List.of("true","false").contains(enabled)) throw new IllegalStateException("BOOTSTRAP_ENABLED must be true or false.");
            if (!Boolean.parseBoolean(enabled)) return;
            for (var entry:Map.of("ADMIN","admin","INVENTORY","inventario","SUPERVISOR","supervisor","CONSULTATION","consulta").entrySet()) {
                String password=environment.getRequiredProperty("BOOTSTRAP_"+entry.getKey()+"_PASSWORD");
                if (password.isBlank() || password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>72) throw new IllegalStateException("Invalid bootstrap password.");
                accounts.createInitial(entry.getValue(),entry.getValue(),passwords.encode(password),entry.getKey());
            }
        };
    }
}
