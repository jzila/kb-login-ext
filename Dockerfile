FROM debian:jessie
MAINTAINER John Zila <john@jzila.com>

EXPOSE 8084

RUN apt-get update && apt-get install -y bash git python g++ make curl
RUN curl -sL https://deb.nodesource.com/setup_5.x | bash -
RUN apt-get install -y nodejs

COPY package.json package.json
COPY demo-server demo-server

RUN npm install

ENTRYPOINT ["npm", "start"]
