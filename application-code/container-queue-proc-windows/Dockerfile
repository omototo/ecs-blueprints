FROM mcr.microsoft.com/windows/servercore:ltsc2019

# Install Python
RUN powershell.exe -Command \
        $ErrorActionPreference = 'Stop'; \
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
        wget https://www.python.org/ftp/python/3.9.6/python-3.9.6-amd64.exe -OutFile c:\temp\python-3.9.6-amd64.exe; \
        Start-Process c:\temp\python-3.9.6-amd64.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
        Remove-Item -Force -Recurse c:\temp\*

# Install pip
RUN python -m ensurepip --upgrade

# Setup directory structure
RUN powershell -Command \
        New-Item -ItemType Directory -Force -Path C:\app; \
        New-Item -ItemType Directory -Force -Path C:\temp\ecsproc

# Set working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY ./src /app

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Run app.py when the container launches
CMD ["python", "app.py"]