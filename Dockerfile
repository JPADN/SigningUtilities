FROM maven:3.8.5-openjdk-17 AS builder
WORKDIR /app
COPY pom.xml ./
RUN mvn dependency:go-offline
COPY src src
RUN mvn clean package

FROM openjdk:17
WORKDIR /app
COPY --from=builder /app/target/signingutilities-1.0.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
