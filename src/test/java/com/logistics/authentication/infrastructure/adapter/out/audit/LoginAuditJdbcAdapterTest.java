package com.logistics.authentication.infrastructure.adapter.out.audit;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class LoginAuditJdbcAdapterTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @InjectMocks
    private LoginAuditJdbcAdapter adapter;

    @Test
    void recordLoginAttempt_callsJdbcTemplateUpdate() {
        UUID userId = UUID.randomUUID();

        adapter.recordLoginAttempt(userId, "user@example.com", true, null);

        verify(jdbcTemplate).update(any(PreparedStatementCreator.class));
    }

    @Test
    void recordLoginAttempt_withNullUserId_callsJdbcTemplateUpdate() {
        adapter.recordLoginAttempt(null, "unknown@example.com", false, "USER_NOT_FOUND");

        verify(jdbcTemplate).update(any(PreparedStatementCreator.class));
    }
}
