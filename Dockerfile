FROM openjdk:17
COPY out/artifacts/SigningUtilities_jar/SigningUtilities.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
