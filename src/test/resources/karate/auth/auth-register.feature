Feature: Registro de usuarios (caja negra: particiones y valores límite)

  Background:
    * url baseUrl

  # Partición válida: email bien formado + password válido (8–128, sin espacios)
  Scenario: Registro válido crea solicitud PENDING con ROLE_OPERATOR
    Given path '/api/v1/auth/register'
    And request { email: 'nuevo.operador@logistics.com', password: 'Pruebas2026*' }
    When method POST
    Then status 201
    And match response.status == 'PENDING'
    And match response.email == 'nuevo.operador@logistics.com'
    And match response.userId == '#string'

  # Partición inválida: email ya registrado -> 409
  Scenario: Registro con email duplicado retorna 409
    Given path '/api/v1/auth/register'
    And request { email: 'dup.user@logistics.com', password: 'Pruebas2026*' }
    When method POST
    Then status 201

    Given path '/api/v1/auth/register'
    And request { email: 'dup.user@logistics.com', password: 'Pruebas2026*' }
    When method POST
    Then status 409
    And match response.errorCode == 'AUTH_EMAIL_ALREADY_REGISTERED'

  # Partición inválida: formato de email incorrecto -> 400
  Scenario: Registro con email inválido retorna 400
    Given path '/api/v1/auth/register'
    And request { email: 'esto-no-es-email', password: 'Pruebas2026*' }
    When method POST
    Then status 400
    And match response.errorCode == 'VALIDATION_ERROR'

  # Valor límite inferior: password de 7 caracteres (mínimo es 8) -> 400
  Scenario: Registro con password demasiado corto retorna 400
    Given path '/api/v1/auth/register'
    And request { email: 'corto.pass@logistics.com', password: '1234567' }
    When method POST
    Then status 400
    And match response.errorCode == 'VALIDATION_ERROR'

  # Partición inválida: password con espacios en blanco -> 400
  Scenario: Registro con password con espacios retorna 400
    Given path '/api/v1/auth/register'
    And request { email: 'espacios.pass@logistics.com', password: 'con espacio' }
    When method POST
    Then status 400
    And match response.errorCode == 'VALIDATION_ERROR'
