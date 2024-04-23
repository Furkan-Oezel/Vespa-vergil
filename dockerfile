# image
FROM alpine:latest

# set working directory
WORKDIR /app

# copy bpf program
COPY vergil /app/vergil
