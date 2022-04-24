#!/bin/bash

LOG_DIR=target/log
mkdir -p ${LOG_DIR}

GC_LOG=${LOG_DIR}/gc.log

JAVA_OPTIONS="-XX:+UseShenandoahGC -XX:+UseStringDeduplication"

EXEC_JAR=$(find target -name *.jar)

mvn package spring-boot:repackage

JAR=$(/bin/find target -name authorization-server-*.jar)
if [[ -z "${JAR}" ]] ; then
    echo "Can not find executable jar" >&2
else
    java ${JAVA_OPTIONS} -jar ${JAR} "$@"
fi

