FROM golang:1.23-bookworm AS builder
WORKDIR /go/openssh-iam-ssh-public-key
COPY . .
RUN CGO_ENABLED=0 go install .

FROM scratch
COPY --from=builder /go/bin/openssh-iam-ssh-public-key /sbin/openssh-iam-ssh-public-key
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/sbin/openssh-iam-ssh-public-key"]
