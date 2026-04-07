# ========= BUILD =========
FROM maven:3.9.9-eclipse-temurin-21-alpine AS build
WORKDIR /src

COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src
RUN mvn -DskipTests package


# ========= RUNTIME =========
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

COPY --from=build /src/target/authentication-service.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-Dspring.profiles.active=prod", "-jar", "/app/app.jar"]
