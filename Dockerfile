FROM python:3.12-slim

ADD . /drheader

WORKDIR drheader

RUN pip install .

ENTRYPOINT drheader
