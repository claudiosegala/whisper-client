# BUILD
FROM abilioesteves/gowebbuilder:v0.2.0 as builder

ENV p $GOPATH/src/github.com/abilioesteves/whisper-client

ADD ./ ${p}
WORKDIR ${p}
RUN go get -v ./...

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /whisper-client main.go

## PKG
FROM alpine

COPY --from=builder /whisper-client /

CMD [ "/whisper-client"]
