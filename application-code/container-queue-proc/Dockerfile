FROM public.ecr.aws/docker/library/python:3.12.0b1-slim-buster

RUN mkdir -p /tmp/ecsproc/

WORKDIR /app

COPY ./src /app

RUN pip install -r requirements.txt

ENTRYPOINT python app.py
