FROM python:3.7

WORKDIR /workspaces

# Install Python dependencies from requirements.txt if it exists
COPY requirements.txt requirements_test.txt ./
RUN pip3 install -r requirements.txt -r requirement_tests.txt \
    && pip3 install tox \
    && rm -f requirements.txt requirements_test.txt

# Set the default shell to bash instead of sh
ENV SHELL /bin/bash
