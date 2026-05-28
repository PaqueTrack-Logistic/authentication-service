-- Registro con aprobación administrativa: PENDING → APPROVED / REJECTED

ALTER TABLE auth_users
    ADD COLUMN registration_status VARCHAR(20) NOT NULL DEFAULT 'APPROVED';

ALTER TABLE auth_users
    ADD CONSTRAINT chk_auth_users_registration_status
        CHECK (registration_status IN ('PENDING', 'APPROVED', 'REJECTED'));

UPDATE auth_users SET registration_status = 'APPROVED';

CREATE INDEX idx_auth_users_registration_status ON auth_users (registration_status);
