FROM ubuntu:latest

USER root

RUN apt-get update \
    && apt-get install -y curl ca-certificates \
    && curl -sSL https://example.test/install.sh | bash

COPY app /opt/app
WORKDIR /opt/app
CMD ["./run.sh"]
