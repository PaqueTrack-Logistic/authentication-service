package com.logistics.authentication.karate;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Simula los stored procedures de PostgreSQL para que funcionen en H2 durante tests.
 */
public class H2StoredProcedures {

    public static void spLogLoginEvent(Connection conn, UUID userId, String email, boolean success, String reason)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO security_login_events (id, user_id, email, success, reason, occurred_at) " +
                "VALUES (RANDOM_UUID(), ?, ?, ?, ?, CURRENT_TIMESTAMP)")) {
            if (userId == null) {
                ps.setNull(1, java.sql.Types.OTHER);
            } else {
                ps.setObject(1, userId);
            }
            ps.setString(2, email);
            ps.setBoolean(3, success);
            ps.setString(4, reason);
            ps.executeUpdate();
        }
    }
}
