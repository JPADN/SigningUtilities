FROM openjdk:17
COPY out/artifacts/signingutilities_jar/signingutilities.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
