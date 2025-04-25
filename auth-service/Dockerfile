FROM golang:1.24.2

WORKDIR /app
COPY . .

RUN go mod tidy

CMD ["go", "run", "cmd/api/main.go"]
