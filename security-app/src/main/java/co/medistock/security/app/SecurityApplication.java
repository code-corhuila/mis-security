package co.medistock.security.app;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication(scanBasePackages="co.medistock.security")
public class SecurityApplication {
    public static void main(String[] args) { SpringApplication.run(SecurityApplication.class,args); }
}
