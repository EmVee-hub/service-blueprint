# Non-serving inventory image used only for scanning.
FROM maven:3.9-eclipse-temurin-17 AS dependencies
WORKDIR /demo
COPY pom.xml .
RUN mvn -B -ntp org.apache.maven.plugins:maven-dependency-plugin:3.7.1:copy-dependencies -DincludeScope=runtime -DoutputDirectory=/demo/jars
FROM alpine:3.22
COPY --from=dependencies /demo/jars/ /opt/demo-jars/
CMD ["sh", "-c", "echo 'SCAN ONLY - no Java app started'"]
