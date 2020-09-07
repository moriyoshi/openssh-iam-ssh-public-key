FROM golang:1.15-buster AS builder
WORKDIR /go/openssh-iam-ssh-public-key
COPY . .
RUN CGO_ENABLED=0 go get .

FROM scratch
COPY --from=builder /go/bin/openssh-iam-ssh-public-key /sbin/openssh-iam-ssh-public-key
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/sbin/openssh-iam-ssh-public-key"]
