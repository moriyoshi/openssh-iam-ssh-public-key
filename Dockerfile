FROM golang:1.15-buster AS builder
WORKDIR /go/openssh-iam-ssh-public-key
COPY . .
RUN CGO_ENABLED=0 go get .

FROM scratch
COPY --from=builder /go/bin/openssh-iam-ssh-public-key .
ENTRYPOINT ["/openssh-iam-ssh-public-key"]
