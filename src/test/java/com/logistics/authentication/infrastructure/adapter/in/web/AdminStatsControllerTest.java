package com.logistics.authentication.infrastructure.adapter.in.web;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.logistics.authentication.application.port.in.GetUserRoleStatsUseCase;
import com.logistics.authentication.domain.readmodel.RoleUserCount;

@ExtendWith(MockitoExtension.class)
class AdminStatsControllerTest {

    private MockMvc mockMvc;

    @Mock
    private GetUserRoleStatsUseCase getUserRoleStatsUseCase;

    @InjectMocks
    private AdminStatsController adminStatsController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(adminStatsController).build();
    }

    @Test
    void usersByRole_returns200WithStats() throws Exception {
        when(getUserRoleStatsUseCase.getUsersByRole())
                .thenReturn(List.of(
                        new RoleUserCount("ROLE_ADMIN", 2),
                        new RoleUserCount("ROLE_USER", 15)));

        mockMvc.perform(get("/api/v1/admin/stats/users-by-role"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rows").isArray())
                .andExpect(jsonPath("$.rows.length()").value(2))
                .andExpect(jsonPath("$.rows[0].roleName").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$.rows[0].userCount").value(2))
                .andExpect(jsonPath("$.rows[1].roleName").value("ROLE_USER"))
                .andExpect(jsonPath("$.rows[1].userCount").value(15));
    }

    @Test
    void usersByRole_returnsEmptyList() throws Exception {
        when(getUserRoleStatsUseCase.getUsersByRole())
                .thenReturn(List.of());

        mockMvc.perform(get("/api/v1/admin/stats/users-by-role"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rows").isArray())
                .andExpect(jsonPath("$.rows.length()").value(0));
    }
}
