#!/bin/sh

GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap main.go
docker buildx build --platform linux/amd64 --provenance=false -t csgy9223:container-lambda .
docker tag csgy9223:container-lambda 468204078736.dkr.ecr.ap-southeast-2.amazonaws.com/csgy9223/container-lambda:latest
docker push 468204078736.dkr.ecr.ap-southeast-2.amazonaws.com/csgy9223/container-lambda:latest

AWS_REGION=ap-southeast-2 aws lambda update-function-code --function-name container-lambda --image-uri 468204078736.dkr.ecr.ap-southeast-2.amazonaws.com/csgy9223/container-lambda:latest
