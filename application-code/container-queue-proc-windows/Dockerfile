FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019

RUN mkdir -p /tmp/ecsproc/

WORKDIR /app

COPY ./src /app

RUN pip install -r requirements.txt

ENTRYPOINT python app.py