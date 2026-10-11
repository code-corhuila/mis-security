package co.medistock.security.core;
import java.util.List;
import java.util.UUID;
public record Account(UUID id, String username, String displayName, String passwordHash, boolean active, List<String> roles) {
    public Account {
        roles = List.copyOf(roles);
        if (id == null || username == null || displayName == null || passwordHash == null || roles.isEmpty()
                || !List.of("ADMIN", "INVENTORY", "SUPERVISOR", "CONSULTATION").containsAll(roles))
            throw new IllegalArgumentException("Invalid account.");
    }
}
