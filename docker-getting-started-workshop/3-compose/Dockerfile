FROM alpine:3.7
RUN apk update && apk add netcat-openbsd
ADD ./server.sh /server.sh
ADD ./client.sh /client.sh
EXPOSE 8080
ENTRYPOINT [ "sh" ]