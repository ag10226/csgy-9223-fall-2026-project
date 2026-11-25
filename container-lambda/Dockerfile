FROM public.ecr.aws/lambda/provided:al2023
COPY ./bootstrap ./main
COPY ./predicate.json ./predicate.json
ENTRYPOINT [ "./main" ]
