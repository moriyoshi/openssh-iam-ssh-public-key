# openssh-iam-ssh-public-key

This is a tiny program that retrieves registered SSH public keys for a specified IAM user and prints them to standard output.

## Synopsis

```
$ openssh-iam-ssh-public-key -user [USER]
```

`-user` option can be omitted, and output the keys for all the users then.

## Configuration

In addition to the default AWS SDK configuration scheme, it supports STS credentials for a assumed role through the following environment variables:

* `AWS_STS_SOURCE_PROFILE`

    This specifies the AWS profile in ~/.aws/config used for retrieving temporary credentials.

* `AWS_STS_ASSUME_ROLE_ARN`

    This specifies the ARN for the assumed (target) IAM role.

This program is particularly useful if you have the following setting in `/etc/ssh/sshd_config`:

```
AuthorizedKeysCommand openssh-iam-ssh-public-key -user %u
```

which enables one whose unix account name corresponds to an IAM user to get authenticated through the SSH keys associated in IAM.
