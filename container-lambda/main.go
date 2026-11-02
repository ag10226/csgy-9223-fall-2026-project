package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	cosignattest "github.com/sigstore/cosign/v3/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	cosignsign "github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

func handler(_ context.Context, event events.CloudWatchEvent) error {
	fmt.Println("PRINTING THE EVENT")
	fmt.Println(event)
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
			NewBundleFormat: true,
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
		NewBundleFormat:    true,
		RegistryClientOpts: []remote.Option{remote.WithAuthFromKeychain(authn.NewKeychainFromHelper(ecrHelper))},
		RekorEntryType:     "intoto",
	}

	err := attestCmd.Exec(ctx, imageRef)
	if err != nil {
		log.Fatalf("failed to attest image: %v", err)
	}
}

func main() {
	// lambda.Start(handler)
	ctx := context.Background()
	sign(ctx,
		"468204078736.dkr.ecr.ap-southeast-2.amazonaws.com/ag/test-repo@sha256:5099b89d7666cc2186cad769ddc262ddc7c335b33f5fe79f9ffe50a01282b23e",
		"7f76b72a-1725-4649-9035-2ea02ab2e865")
	attest(ctx,
		"468204078736.dkr.ecr.ap-southeast-2.amazonaws.com/ag/test-repo@sha256:5099b89d7666cc2186cad769ddc262ddc7c335b33f5fe79f9ffe50a01282b23e",
		"7f76b72a-1725-4649-9035-2ea02ab2e865")
}
