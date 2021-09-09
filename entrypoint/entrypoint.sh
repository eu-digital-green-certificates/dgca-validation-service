#!/bin/sh
sh docker-entrypoint.sh nginx &
sh -c "java -jar /app/app.jar"
