FROM eclipse-temurin:21-jdk AS build
WORKDIR /app
COPY gradlew .
COPY gradle ./gradle
COPY build.gradle settings.gradle ./
RUN ./gradlew dependencies --no-daemon -q
COPY src ./src
RUN ./gradlew bootJar --no-daemon -q

FROM eclipse-temurin:21-jre AS runtime
WORKDIR /app

RUN groupadd -g 1001 nipca \
 && useradd -u 1001 -g nipca -M -s /sbin/nologin nipca \
 && mkdir -p /data && chown nipca:nipca /data

COPY --from=build /app/build/libs/*.jar app.jar
RUN chown nipca:nipca app.jar

USER nipca
EXPOSE 17440

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:17440/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
