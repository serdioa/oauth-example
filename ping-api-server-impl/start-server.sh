#!/bin/bash

CONFIG_ID="$1"
if [[ -z "$CONFIG_ID" ]]; then
    CONFIG_ID=1
fi
CONFIG_FILE="src/main/config/ping-api-server-${CONFIG_ID}.properties"
echo "CONFIG_FILE=${CONFIG_FILE}"
if [[ ! -r "$CONFIG_FILE" ]]; then
    echo "Configuration file ${CONFIG_FILE} does not exist or is not readable" 1>&2
    exit 1
fi
SPRING_OPTIONS="--spring.config.location=${CONFIG_FILE}"

JAVA_OPTIONS="-XX:+UseShenandoahGC -XX:+UseStringDeduplication"

mvn package spring-boot:repackage

JAR=$(/bin/find target -name ping-api-server-impl-*.jar)
if [[ -z "${JAR}" ]] ; then
    echo "Can not find executable jar" >&2
else
    java ${JAVA_OPTIONS} -jar ${JAR} ${SPRING_OPTIONS} "$@"
fi
