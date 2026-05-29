Feature: Refresh de tokens

  Background:
    * url baseUrl

  # Flujo válido: login -> refresh rota y devuelve nuevos tokens
  Scenario: Refrescar con un refresh token válido retorna nuevos tokens
    Given path '/api/v1/auth/login'
    And request { email: 'admin@logistics.com', password: 'password' }
    When method POST
    Then status 200
    * def rt = response.refreshToken

    Given path '/api/v1/auth/refresh'
    And request { refreshToken: '#(rt)' }
    When method POST
    Then status 200
    And match response.accessToken == '#string'
    And match response.refreshToken == '#string'

  # Partición inválida: refresh token inexistente/ilegible -> 401
  Scenario: Refrescar con un token inválido retorna 401
    Given path '/api/v1/auth/refresh'
    And request { refreshToken: 'token-que-no-existe' }
    When method POST
    Then status 401
    And match response.errorCode == '#string'
