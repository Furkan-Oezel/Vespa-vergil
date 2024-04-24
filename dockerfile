# image
FROM alpine:latest

# set working directory
WORKDIR /app

# copy bpf program
COPY vergil /app/vergil

# Command to run when the container starts
ENTRYPOINT ["./vergil"]
