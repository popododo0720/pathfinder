package cloud

import (
	"context"
	"crypto/tls"
	"os"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/config"
)

func NewNetworkClient(ctx context.Context) (*gophercloud.ServiceClient, error) {
	authOptions := gophercloud.AuthOptions{
		IdentityEndpoint: os.Getenv("OS_AUTH_URL"),
		Username:         os.Getenv("OS_USERNAME"),
		Password:         os.Getenv("OS_PASSWORD"),
		DomainID:         os.Getenv("OS_USER_DOMAIN_ID"),
		DomainName:       os.Getenv("OS_USER_DOMAIN_NAME"),
		Scope: &gophercloud.AuthScope{
			ProjectID:   os.Getenv("OS_PROJECT_ID"),
			ProjectName: os.Getenv("OS_PROJECT_NAME"),
			DomainID:    os.Getenv("OS_PROJECT_DOMAIN_ID"),
			DomainName:  os.Getenv("OS_PROJECT_DOMAIN_NAME"),
		},
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	provider, err := config.NewProviderClient(
		ctx,
		authOptions,
		config.WithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, err
	}

	return openstack.NewNetworkV2(
		provider,
		gophercloud.EndpointOpts{
			Region: os.Getenv("OS_REGION_NAME"),
		},
	)
}
