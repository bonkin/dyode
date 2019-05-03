# `docker build --pull --tag dyode:0.1`

FROM python:2.7-stretch

RUN apt-get update
RUN apt-get install sudo

COPY requirements.txt /
RUN pip install -r /requirements.txt

RUN apt-get install libssl-dev libffi-dev
RUN pip install cryptography pyasn1-modules

COPY . /app
RUN mkdir /send
RUN mkdir /receive

WORKDIR /app
RUN dpkg -i udpcast_20120424_amd64.deb
RUN apt-get install net-tools
