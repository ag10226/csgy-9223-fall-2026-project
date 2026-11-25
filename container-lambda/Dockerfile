FROM golang:1.27 AS build
WORKDIR /container-lambda
# Copy dependencies list
COPY go.mod go.sum ./
# Build with optional lambda.norpc tag
COPY main.go .
RUN go build -ldflags="-s -w" -tags lambda.norpc -o main main.go
# Copy artifacts to a clean image
FROM public.ecr.aws/lambda/provided:al2023
COPY --from=build /container-lambda/main ./main
ENTRYPOINT [ "./main" ]
