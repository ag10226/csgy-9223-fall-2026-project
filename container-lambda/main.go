package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	cosignattest "github.com/sigstore/cosign/v3/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	cosignsign "github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

var imageRefTemplate string = "%s.dkr.ecr.%s.amazonaws.com/%s@%s"
var keyID string = "7f76b72a-1725-4649-9035-2ea02ab2e865"

type ECREventDetail struct {
	Result         string `json:"result"`
	RepositoryName string `json:"repository-name"`
	ImageDigest    string `json:"image-digest"`
	ActionType     string `json:"action-type"`
	ImageTag       string `json:"image-tag"`
}

func handler(ctx context.Context, event events.CloudWatchEvent) error {
	log.Printf("received ECR event: %v", event)
	var eventDetail ECREventDetail
	err := json.Unmarshal(event.Detail, &eventDetail)
	if err != nil {
		log.Fatalf("error parsing event: %v", err)
	}

	imageRef := fmt.Sprintf(imageRefTemplate, event.AccountID, event.Region, eventDetail.RepositoryName, eventDetail.ImageDigest)

	sign(ctx, imageRef, keyID)
	log.Printf("finished signing image %s", imageRef)
	attest(ctx, imageRef, keyID)
	log.Printf("finished attesting image %s", imageRef)

	return nil
}

func sign(ctx context.Context, imageRef string, keyID string) {
	clientFactory := ecr.WithClientFactory(api.DefaultClientFactory{})
	ecrHelper := ecr.NewECRHelper(clientFactory)

	err := cosignsign.SignCmd(
		ctx,
		&options.RootOptions{
			Timeout: 3 * time.Minute,
		},
		options.KeyOpts{
			KeyRef: fmt.Sprintf("awskms:///%s", keyID),
		},
		options.SignOptions{
			TlogUpload:       false,
			Upload:           true,
			SkipConfirmation: true,
			Registry: options.RegistryOptions{
				Keychain: authn.NewKeychainFromHelper(ecrHelper),
			},
			NewBundleFormat: false,
		},
		[]string{imageRef},
	)

	if err != nil {
		log.Fatalf("failed to sign image: %v", err)
	}
}

func attest(ctx context.Context, imageRef, keyID string) {
	clientFactory := ecr.WithClientFactory(api.DefaultClientFactory{})
	ecrHelper := ecr.NewECRHelper(clientFactory)

	attestCmd := cosignattest.AttestCommand{
		KeyRef:             fmt.Sprintf("awskms:///%s", keyID),
		TlogUpload:         false,
		Keychain:           authn.NewKeychainFromHelper(ecrHelper),
		PredicatePath:      "./predicate.json",
		PredicateType:      "custom",
		NewBundleFormat:    false,
		RegistryClientOpts: []remote.Option{remote.WithAuthFromKeychain(authn.NewKeychainFromHelper(ecrHelper))},
		RekorEntryType:     "intoto",
	}

	err := attestCmd.Exec(ctx, imageRef)
	if err != nil {
		log.Fatalf("failed to attest image: %v", err)
	}
}

func main() {
	lambda.Start(handler)
}
