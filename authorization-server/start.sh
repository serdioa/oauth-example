#!/bin/bash

LOG_DIR=target/log
mkdir -p ${LOG_DIR}

GC_LOG=${LOG_DIR}/gc.log

JAVA_OPTIONS="-XX:+UseShenandoahGC -XX:+UseStringDeduplication"

EXEC_JAR=$(find target -name *.jar)

java ${JAVA_OPTIONS} -jar ${EXEC_JAR} \
    --spring.config.location=file:src/config/authorization-server.properties \
    "$@"

