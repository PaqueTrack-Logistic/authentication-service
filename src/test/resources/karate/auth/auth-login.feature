Feature: Authentication Login API
  Background:
    * url baseUrl

  # CP-15-01: Login with valid credentials
  Scenario: Login with valid credentials returns access and refresh tokens
    Given path '/api/v1/auth/login'
    And request { email: 'admin@logistics.com', password: 'password' }
    When method POST
    Then status 200
    And match response.accessToken == '#string'
    And match response.tokenType == 'Bearer'
    And match response.expiresIn == '#number'
    And match response.roles == '#array'
    And match response.refreshToken == '#string'
    And match response.refreshExpiresIn == '#number'

  # CP-15-02: Login denied - wrong password
  Scenario: Login with wrong password returns 401
    Given path '/api/v1/auth/login'
    And request { email: 'admin@logistics.com', password: 'wrongpassword' }
    When method POST
    Then status 401
    And match response.errorCode == '#string'
    And match response.message == '#string'

  # CP-15-03: Login denied - unregistered email
  Scenario: Login with unregistered email returns 401
    Given path '/api/v1/auth/login'
    And request { email: 'noexiste@logistics.com', password: 'password123' }
    When method POST
    Then status 401
    And match response.errorCode == '#string'
    And match response.message == '#string'

  # CP-15-04: Login denied - missing data
  Scenario: Login with missing data returns 400
    Given path '/api/v1/auth/login'
    And request { email: '', password: '' }
    When method POST
    Then status 400
    And match response.errorCode == 'VALIDATION_ERROR'
