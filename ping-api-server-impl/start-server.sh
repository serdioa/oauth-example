#!/bin/bash

mvn package spring-boot:repackage

JAR=$(/bin/find target -name ping-api-server-impl-*.jar)
if [[ -z "${JAR}" ]] ; then
    echo "Can not find executable jar" >&2
else
    java -jar ${JAR} "$@"
fi
