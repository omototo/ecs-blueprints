FROM mcr.microsoft.com/windows/servercore:ltsc2019

# Install Python, pip
ADD https://www.python.org/ftp/python/3.12.0/python-3.12.0.exe ./ 
RUN python-3.12.0.exe /quiet InstallAllUsers=1 PrependPath=1

RUN mkdir -p /tmp/ecsproc/

WORKDIR /app

COPY ./src /app

RUN pip install -r requirements.txt

ENTRYPOINT python app.py
