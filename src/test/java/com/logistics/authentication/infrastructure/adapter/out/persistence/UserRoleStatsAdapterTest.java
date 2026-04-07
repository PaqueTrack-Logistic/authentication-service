package com.logistics.authentication.infrastructure.adapter.out.persistence;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.logistics.authentication.domain.readmodel.RoleUserCount;
import com.logistics.authentication.infrastructure.adapter.out.persistence.repository.UserJpaRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserRoleStatsAdapterTest {

    @Mock
    private UserJpaRepository userJpaRepository;

    @InjectMocks
    private UserRoleStatsAdapter adapter;

    @Test
    void countUsersGroupedByRole_delegatesToJpaAndMapsResults() {
        List<Object[]> rawRows = List.of(
                new Object[]{"ADMIN", 5L},
                new Object[]{"USER", 10L}
        );
        when(userJpaRepository.countUsersGroupedByRole()).thenReturn(rawRows);

        List<RoleUserCount> result = adapter.countUsersGroupedByRole();

        assertThat(result).hasSize(2);
        assertThat(result.get(0).roleName()).isEqualTo("ADMIN");
        assertThat(result.get(0).userCount()).isEqualTo(5L);
        assertThat(result.get(1).roleName()).isEqualTo("USER");
        assertThat(result.get(1).userCount()).isEqualTo(10L);
        verify(userJpaRepository).countUsersGroupedByRole();
    }

    @Test
    void countUsersGroupedByRole_returnsEmptyListWhenNoData() {
        when(userJpaRepository.countUsersGroupedByRole()).thenReturn(List.of());

        List<RoleUserCount> result = adapter.countUsersGroupedByRole();

        assertThat(result).isEmpty();
    }
}
