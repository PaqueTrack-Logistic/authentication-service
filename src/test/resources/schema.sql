-- Tabla de auditoría (no gestionada por JPA)
CREATE TABLE IF NOT EXISTS security_login_events (
    id UUID DEFAULT RANDOM_UUID() PRIMARY KEY,
    user_id UUID,
    email VARCHAR(255) NOT NULL,
    success BOOLEAN NOT NULL,
    reason VARCHAR(500),
    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Stored procedure H2-compatible
CREATE ALIAS IF NOT EXISTS sp_log_login_event FOR "com.logistics.authentication.karate.H2StoredProcedures.spLogLoginEvent";
