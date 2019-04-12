FROM alpine

COPY init.sh /init.sh 

RUN chmod +x init.sh