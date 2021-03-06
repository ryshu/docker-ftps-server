FROM python:2-slim

COPY . /app/
WORKDIR /app/
RUN pip install -r requirements.txt
RUN mkdir /ftp_root

EXPOSE 21

VOLUME /app/config

ENTRYPOINT python -u entrypoint.py
