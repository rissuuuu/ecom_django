# create image sudo docker build -t project/backend:0.0.1 .
# pull official base image
FROM python:3.6-slim

# set work directory
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY ./dependencies/apt_requirements.txt /usr/src/app/apt_requirements.txt
#install application
RUN apt-get update && \
    apt-get install -y $(cat ./apt_requirements.txt) && \
    apt-get clean

# install dependencies

COPY ./dependencies/requirements.txt /usr/src/app/requirements.txt
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . /usr/src/app/

