# ---------------------------------------------------------------------------
# DocuTrust backend image
#
# Multi-stage: the build stage carries the JDK, Maven and the full dependency
# cache; the runtime stage carries only a JRE and the application jar. The
# published image therefore has no compiler, no build tooling and no source.
# ---------------------------------------------------------------------------

# ------------------------------- build -------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /build

# Dependencies are resolved before the source is copied, so editing code does
# not invalidate the cached dependency layer.
COPY pom.xml .
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B clean package -DskipTests

# ------------------------------ runtime ------------------------------------
FROM eclipse-temurin:21-jre-alpine AS runtime

# Run as an unprivileged user. A container process running as root that is
# compromised has a far larger blast radius, including on any mounted volume.
RUN addgroup -S docutrust && adduser -S -G docutrust docutrust

WORKDIR /app

# wget is used by the compose healthcheck.
RUN apk add --no-cache wget

COPY --from=build /build/target/*.jar /app/application.jar

# Writable only where the application genuinely needs to write.
RUN mkdir -p /app/.data && chown -R docutrust:docutrust /app

USER docutrust

EXPOSE 8080

# Container-aware heap sizing: without this the JVM can size the heap from the
# host's memory rather than the container limit and be OOM-killed.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/application.jar"]
