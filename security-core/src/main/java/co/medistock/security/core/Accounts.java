package co.medistock.security.core;
import java.util.Optional;
import java.util.UUID;
public interface Accounts {
    Optional<Account> byUsername(String username);
    Optional<Account> byId(UUID id);
}
