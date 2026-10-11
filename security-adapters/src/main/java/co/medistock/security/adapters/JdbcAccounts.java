package co.medistock.security.adapters;
import co.medistock.security.core.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;
public final class JdbcAccounts implements Accounts {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private static final String SELECT = """
        SELECT u.id, u.username, u.display_name, u.password_hash, u.active, array_agg(r.code ORDER BY r.code) AS roles
        FROM security.user_account u JOIN security.user_role ur ON ur.user_id=u.id
        JOIN security.role r ON r.code=ur.role_code
        """;
    public JdbcAccounts(JdbcTemplate jdbc, TransactionTemplate transactions) { this.jdbc=jdbc; this.transactions=transactions; }
    private Optional<Account> find(String predicate, Object value) {
        return jdbc.query(SELECT + predicate + " GROUP BY u.id", (rs, row) ->
            new Account(rs.getObject("id", UUID.class), rs.getString("username"), rs.getString("display_name"),
                rs.getString("password_hash"), rs.getBoolean("active"), Arrays.asList((String[]) rs.getArray("roles").getArray())), value).stream().findFirst();
    }
    public Optional<Account> byUsername(String username) { return find(" WHERE u.username=?", username); }
    public Optional<Account> byId(UUID id) { return find(" WHERE u.id=?", id); }
    public void createInitial(String username, String displayName, String hash, String role) {
        transactions.executeWithoutResult(status -> {
            var id = UUID.randomUUID();
            int inserted = jdbc.update("INSERT INTO security.user_account(id,username,display_name,password_hash,active) VALUES(?,?,?,?,true) ON CONFLICT(username) DO NOTHING", id, username, displayName, hash);
            if (inserted == 1) jdbc.update("INSERT INTO security.user_role(user_id,role_code) VALUES(?,?)", id, role);
        });
    }
}
