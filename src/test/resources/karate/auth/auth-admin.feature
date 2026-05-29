Feature: Administración de usuarios y control de acceso por rol (RBAC)

  Background:
    * url baseUrl
    # Iniciar sesión como administrador y guardar el token
    Given path '/api/v1/auth/login'
    And request { email: 'admin@logistics.com', password: 'password' }
    When method POST
    Then status 200
    * def adminToken = response.accessToken

  # SecurityConfig: sin token -> 401 (entry point)
  Scenario: Acceder a un endpoint de admin sin token retorna 401
    Given path '/api/v1/admin/users/pending'
    When method GET
    Then status 401

  # ROLE_ADMIN puede listar pendientes
  Scenario: Admin lista solicitudes pendientes
    Given path '/api/v1/admin/users/pending'
    And header Authorization = 'Bearer ' + adminToken
    When method GET
    Then status 200

  # ROLE_ADMIN obtiene roles asignables
  Scenario: Admin obtiene los roles asignables
    Given path '/api/v1/admin/users/assignable-roles'
    And header Authorization = 'Bearer ' + adminToken
    When method GET
    Then status 200

  # ROLE_ADMIN obtiene estadísticas por rol
  Scenario: Admin obtiene estadísticas de usuarios por rol
    Given path '/api/v1/admin/stats/users-by-role'
    And header Authorization = 'Bearer ' + adminToken
    When method GET
    Then status 200

  # Flujo completo: registrar -> aprobar como OPERATOR -> login -> RBAC 403
  Scenario: Un operador aprobado no puede acceder a endpoints de admin (403)
    # 1) registrar nuevo usuario (queda PENDING)
    Given path '/api/v1/auth/register'
    And request { email: 'op.rbac@logistics.com', password: 'Pruebas2026*' }
    When method POST
    Then status 201
    * def newUserId = response.userId

    # 2) el admin lo aprueba con ROLE_OPERATOR
    Given path 'api/v1/admin/users', newUserId, 'approve'
    And header Authorization = 'Bearer ' + adminToken
    And request { role: 'ROLE_OPERATOR' }
    When method POST
    Then status 200

    # 3) el operador inicia sesión
    Given path '/api/v1/auth/login'
    And request { email: 'op.rbac@logistics.com', password: 'Pruebas2026*' }
    When method POST
    Then status 200
    * def opToken = response.accessToken

    # 4) el operador intenta un endpoint de admin -> 403 (access denied)
    Given path '/api/v1/admin/users/pending'
    And header Authorization = 'Bearer ' + opToken
    When method GET
    Then status 403

  # Rechazo de una solicitud por el admin
  Scenario: Admin rechaza una solicitud de registro
    Given path '/api/v1/auth/register'
    And request { email: 'op.reject@logistics.com', password: 'Pruebas2026*' }
    When method POST
    Then status 201
    * def rejectId = response.userId

    Given path 'api/v1/admin/users', rejectId, 'reject'
    And header Authorization = 'Bearer ' + adminToken
    When method POST
    Then status 200
    And match response.status == 'REJECTED'
