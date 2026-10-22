# Build on the disconnected Linux server from its already-loaded base image.
# Build context contains the verified existing spring-boot-application.jar only.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY spring-boot-application.jar /app/spring-boot-application.jar
ENV SERVER_ADDRESS=0.0.0.0 SERVER_PORT=8080 SERVER_SERVLET_CONTEXT_PATH=/log4shell LOGGING_CONFIG=classpath:log4j2-spring.xml
USER 65532:65532
ENTRYPOINT ["java", "-jar", "/app/spring-boot-application.jar"]
