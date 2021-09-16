FROM golang:alpine as builder

RUN apk add --no-cache \
        git \
        make \
        gcc \
        musl-dev

ENV REPOSITORY github.com/vulsio/gost
COPY . $GOPATH/src/$REPOSITORY
RUN cd $GOPATH/src/$REPOSITORY && make install


FROM alpine:3.14

ENV LOGDIR /var/log/gost
ENV WORKDIR /gost

RUN apk add --no-cache ca-certificates git \
    && mkdir -p $WORKDIR $LOGDIR

COPY --from=builder /go/bin/gost /usr/local/bin/

VOLUME ["$WORKDIR", "$LOGDIR"]
WORKDIR $WORKDIR
ENV PWD $WORKDIR

ENTRYPOINT ["gost"]
CMD ["--help"]
