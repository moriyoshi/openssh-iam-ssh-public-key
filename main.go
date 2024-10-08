// Copyright (c) 2020 Moriyoshi Koizumi
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iam_types "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var progName = filepath.Base(os.Args[0])
var buildIamClient func(ctx context.Context) (*iam.Client, error) = _buildIamClient

func getAwsConfig(ctx context.Context) (cfg aws.Config, err error) {
	stsAssumeRoleArn := os.Getenv("AWS_STS_ASSUME_ROLE_ARN")
	if stsAssumeRoleArn != "" {
		var extraOptions []func(*config.LoadOptions) error
		stsSourceProfile := os.Getenv("AWS_STS_SOURCE_PROFILE")
		if stsSourceProfile != "" {
			extraOptions = append(extraOptions, config.WithSharedConfigProfile(stsSourceProfile))
		}
		cfg, err = config.LoadDefaultConfig(ctx, extraOptions...)
		if err != nil {
			return
		}
		sts := sts.NewFromConfig(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(sts, stsAssumeRoleArn)
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
		if err != nil {
			return
		}
	}
	return
}

func _buildIamClient(ctx context.Context) (*iam.Client, error) {
	cfg, err := getAwsConfig(ctx)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(cfg), nil
}

func listUsers(ctx context.Context, client *iam.Client, callback func([]iam_types.User) error) error {
	var marker *string
	for {
		resp, err := client.ListUsers(
			ctx,
			&iam.ListUsersInput{
				Marker: marker,
			},
		)
		err = callback(resp.Users)
		if err != nil {
			return err
		}
		if !resp.IsTruncated {
			break
		} else {
			if resp.Marker == nil {
				return fmt.Errorf("resp.IsTruncated is true, but no marker is given")
			}
			marker = resp.Marker
		}
	}
	return nil
}

func listSSHPublicKeys(ctx context.Context, client *iam.Client, userName string, callback func([]iam_types.SSHPublicKeyMetadata) error) error {
	var marker *string
	for {
		resp, err := client.ListSSHPublicKeys(
			ctx,
			&iam.ListSSHPublicKeysInput{
				UserName: &userName,
				Marker:   marker,
			},
		)
		if err != nil {
			return err
		}
		err = callback(resp.SSHPublicKeys)
		if err != nil {
			return err
		}
		if !resp.IsTruncated {
			break
		} else {
			if resp.Marker == nil {
				return fmt.Errorf("resp.IsTruncated is true, but no marker is given")
			}
			marker = resp.Marker
		}
	}
	return nil
}

func listActiveSSHKeyIds(ctx context.Context, client *iam.Client, userName string) ([]string, error) {
	var keyIds []string
	// list active keys
	err := listSSHPublicKeys(
		ctx, client, userName,
		func(metadata []iam_types.SSHPublicKeyMetadata) error {
			for _, m := range metadata {
				if m.Status == iam_types.StatusTypeActive {
					keyIds = append(keyIds, *m.SSHPublicKeyId)
				}
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return keyIds, nil
}

func mapKeyIdsToSshPublicKeys(ctx context.Context, client *iam.Client, parallelism int, userName string, keyIds []string) ([]string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// build a request
	sema := make(chan struct{}, 4)
	errChan := make(chan error, len(sema))
	resultChan := make(chan string, len(sema))

	var sshKeys []string
	var lastError error
	var wg sync.WaitGroup

	wg.Add(1)
	go func(c int) {
		defer wg.Done()
	outer:
		for i := 0; i < c; i++ {
			select {
			case <-ctx.Done():
				break outer
			case sshKey := <-resultChan:
				if sshKey != "" {
					sshKeys = append(sshKeys, sshKey)
				}
			case err := <-errChan:
				lastError = err
				cancel()
			}
		}
		close(resultChan)
		close(errChan)
	}(len(keyIds))

	for _, keyId := range keyIds {
		sema <- struct{}{}
		wg.Add(1)
		go func(keyId string) {
			defer func() { <-sema }()
			defer wg.Done()
			out, err := client.GetSSHPublicKey(
				ctx,
				&iam.GetSSHPublicKeyInput{
					Encoding:       iam_types.EncodingTypeSsh,
					UserName:       &userName,
					SSHPublicKeyId: &keyId,
				},
			)
			if err != nil {
				errChan <- err
			} else {
				resultChan <- *out.SSHPublicKey.SSHPublicKeyBody
			}
		}(keyId)
	}

	wg.Wait()
	return sshKeys, lastError
}

func mapUsersToSshPublicKeys(ctx context.Context, client *iam.Client, parallelism int, userNames []string) ([]string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// build a request
	sema := make(chan struct{}, parallelism)
	errChan := make(chan error, len(sema))
	resultChan := make(chan []string, len(sema))

	var sshKeys []string
	var lastError error
	var wg sync.WaitGroup

	wg.Add(1)
	go func(c int) {
		defer wg.Done()
	outer:
		for i := 0; i < c; i++ {
			select {
			case <-ctx.Done():
				break outer
			case sshKeysChunk := <-resultChan:
				if sshKeysChunk != nil {
					sshKeys = append(sshKeys, sshKeysChunk...)
				}
			case err := <-errChan:
				lastError = err
				cancel()
			}
		}
		close(resultChan)
		close(errChan)
	}(len(userNames))

	for _, userName := range userNames {
		sema <- struct{}{}
		wg.Add(1)
		go func(userName string) {
			defer func() { <-sema }()
			defer wg.Done()
			sshKeysChunk, err := getSshPublicKeysInner(ctx, client, parallelism, userName)
			if err != nil {
				errChan <- err
			} else {
				resultChan <- sshKeysChunk
			}
		}(userName)
	}

	wg.Wait()
	return sshKeys, lastError
}

func getSshPublicKeysInner(ctx context.Context, client *iam.Client, parallelism int, userName string) ([]string, error) {
	keyIds, err := listActiveSSHKeyIds(ctx, client, userName)
	if err != nil {
		return nil, err
	}
	return mapKeyIdsToSshPublicKeys(ctx, client, parallelism, userName, keyIds)
}

func getSshPublicKeys(ctx context.Context, client *iam.Client, parallelism int, userName string) ([]string, error) {
	if userName == "" {
		var userNames []string
		err := listUsers(ctx, client, func(users []iam_types.User) error {
			for _, user := range users {
				userNames = append(userNames, *user.UserName)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return mapUsersToSshPublicKeys(ctx, client, parallelism, userNames)
	} else {
		return getSshPublicKeysInner(ctx, client, parallelism, userName)
	}
}

func do(ctx context.Context) error {
	var userName string
	var parallelism int

	flagParser := flag.NewFlagSet(
		progName,
		flag.ExitOnError,
	)
	flagParser.StringVar(&userName, "user", "", "user name")
	err := flagParser.Parse(os.Args[1:])
	if err != nil {
		return err
	}
	flagParser.IntVar(&parallelism, "parallelism", 4, "paralellism")

	client, err := buildIamClient(ctx)
	if err != nil {
		return err
	}

	keys, err := getSshPublicKeys(ctx, client, parallelism, userName)
	if err != nil {
		return err
	}
	for _, key := range keys {
		fmt.Println(key)
	}
	return nil
}

func putError(msg string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", progName, msg)
}

func main() {
	err := do(context.Background())
	if err != nil {
		putError(err.Error())
		os.Exit(1)
	}
}
