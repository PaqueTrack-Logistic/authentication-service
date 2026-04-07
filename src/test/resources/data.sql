-- Seed data para tests de integración (Karate)
-- Password: password123 (BCrypt cost 10)
INSERT INTO auth_roles (id, name) VALUES
    ('11111111-1111-1111-1111-111111111111', 'ROLE_ADMIN'),
    ('22222222-2222-2222-2222-222222222222', 'ROLE_OPERATOR');

INSERT INTO auth_users (id, email, password_hash, enabled, failed_login_attempts, created_at, updated_at)
VALUES (
    '33333333-3333-3333-3333-333333333333',
    'admin@logistics.com',
    '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
    TRUE,
    0,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

INSERT INTO auth_user_roles (user_id, role_id) VALUES
    ('33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111');
