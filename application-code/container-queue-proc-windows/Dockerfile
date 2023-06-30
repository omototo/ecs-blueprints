FROM microsoft/aspnet

RUN mkdir -p /tmp/ecsproc/

WORKDIR /app

COPY ./src /app

# Download the Python installer
ADD https://www.python.org/ftp/python/3.9.7/python-3.9.7-amd64.exe /python-installer.exe

# Install Python
RUN ["C:\\Windows\\System32\\cmd.exe", "/C", "C:\\python-installer.exe /quiet InstallAllUsers=1 PrependPath=1"]

# Remove the installer
RUN ["C:\\Windows\\System32\\cmd.exe", "/C", "del C:\\python-installer.exe"]

# Verify python was installed
RUN ["C:\\Windows\\System32\\cmd.exe", "/C", "python --version"]

RUN pip install -r requirements.txt

ENTRYPOINT python app.py