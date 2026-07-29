package cloud

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/config"
)

func NewNetworkClient(ctx context.Context) (*gophercloud.ServiceClient, error) {
	authOptions, err := authOptionsFromEnvironment()
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tlsConfigFromEnvironment()
	if err != nil {
		return nil, err
	}
	endpointOptions, err := endpointOptionsFromEnvironment()
	if err != nil {
		return nil, err
	}

	provider, err := config.NewProviderClient(
		ctx,
		authOptions,
		config.WithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, err
	}
	return openstack.NewNetworkV2(provider, endpointOptions)
}

func authOptionsFromEnvironment() (gophercloud.AuthOptions, error) {
	auth, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		if !hasSplitDomainEnvironment() {
			return gophercloud.AuthOptions{}, err
		}
		auth, err = splitDomainAuthOptionsFromEnvironment()
		if err != nil {
			return gophercloud.AuthOptions{}, err
		}
	}

	if value := firstEnvironment("OS_USER_DOMAIN_ID", "OS_DOMAIN_ID"); value != "" {
		auth.DomainID = value
	}
	if value := firstEnvironment("OS_USER_DOMAIN_NAME", "OS_DOMAIN_NAME"); value != "" {
		auth.DomainName = value
	}
	if auth.TenantID == "" && auth.TenantName != "" {
		projectDomainID := os.Getenv("OS_PROJECT_DOMAIN_ID")
		projectDomainName := os.Getenv("OS_PROJECT_DOMAIN_NAME")
		if projectDomainID != "" || projectDomainName != "" {
			auth.Scope = &gophercloud.AuthScope{
				ProjectName: auth.TenantName,
				DomainID:    projectDomainID,
				DomainName:  projectDomainName,
			}
			auth.TenantName = ""
		}
	}
	if strings.Contains(
		strings.ToLower(os.Getenv("OS_AUTH_TYPE")),
		"applicationcredential",
	) {
		auth.Password = ""
		auth.Passcode = ""
	}
	return auth, nil
}

func splitDomainAuthOptionsFromEnvironment() (
	gophercloud.AuthOptions,
	error,
) {
	auth := gophercloud.AuthOptions{
		IdentityEndpoint: os.Getenv("OS_AUTH_URL"),
		UserID:           firstEnvironment("OS_USER_ID", "OS_USERID"),
		Username:         os.Getenv("OS_USERNAME"),
		Password:         os.Getenv("OS_PASSWORD"),
		Passcode:         os.Getenv("OS_PASSCODE"),
		DomainID:         firstEnvironment("OS_USER_DOMAIN_ID", "OS_DOMAIN_ID"),
		DomainName: firstEnvironment(
			"OS_USER_DOMAIN_NAME",
			"OS_DOMAIN_NAME",
		),
		ApplicationCredentialID: os.Getenv(
			"OS_APPLICATION_CREDENTIAL_ID",
		),
		ApplicationCredentialName: os.Getenv(
			"OS_APPLICATION_CREDENTIAL_NAME",
		),
		ApplicationCredentialSecret: os.Getenv(
			"OS_APPLICATION_CREDENTIAL_SECRET",
		),
	}
	if auth.IdentityEndpoint == "" {
		return auth, fmt.Errorf("missing OS_AUTH_URL")
	}

	hasApplicationCredential := auth.ApplicationCredentialID != "" ||
		auth.ApplicationCredentialName != ""
	if hasApplicationCredential && auth.ApplicationCredentialSecret == "" {
		return auth, fmt.Errorf("missing OS_APPLICATION_CREDENTIAL_SECRET")
	}
	if auth.ApplicationCredentialID == "" &&
		auth.ApplicationCredentialName != "" &&
		auth.UserID == "" &&
		auth.Username == "" {
		return auth, fmt.Errorf(
			"application credential name requires OS_USER_ID or OS_USERNAME",
		)
	}
	if !hasApplicationCredential {
		if auth.UserID == "" && auth.Username == "" {
			return auth, fmt.Errorf("missing OS_USER_ID or OS_USERNAME")
		}
		if auth.Password == "" && auth.Passcode == "" {
			return auth, fmt.Errorf("missing OS_PASSWORD")
		}
	}

	projectID := firstEnvironment("OS_PROJECT_ID", "OS_TENANT_ID")
	projectName := firstEnvironment("OS_PROJECT_NAME", "OS_TENANT_NAME")
	switch {
	case os.Getenv("OS_SYSTEM_SCOPE") == "all":
		auth.Scope = &gophercloud.AuthScope{System: true}
	case projectID != "":
		auth.Scope = &gophercloud.AuthScope{ProjectID: projectID}
	case projectName != "":
		auth.Scope = &gophercloud.AuthScope{
			ProjectName: projectName,
			DomainID:    os.Getenv("OS_PROJECT_DOMAIN_ID"),
			DomainName:  os.Getenv("OS_PROJECT_DOMAIN_NAME"),
		}
	}
	return auth, nil
}

func endpointOptionsFromEnvironment() (
	gophercloud.EndpointOpts,
	error,
) {
	value := strings.ToLower(strings.TrimSpace(
		firstEnvironment("OS_INTERFACE", "OS_ENDPOINT_TYPE"),
	))
	availability := gophercloud.AvailabilityPublic
	switch value {
	case "", "public", "publicurl":
	case "internal", "internalurl":
		availability = gophercloud.AvailabilityInternal
	case "admin", "adminurl":
		availability = gophercloud.AvailabilityAdmin
	default:
		return gophercloud.EndpointOpts{},
			fmt.Errorf("unsupported OS_INTERFACE %q", value)
	}
	return gophercloud.EndpointOpts{
		Region:       os.Getenv("OS_REGION_NAME"),
		Availability: availability,
	}, nil
}

func tlsConfigFromEnvironment() (*tls.Config, error) {
	insecure := false
	if raw := strings.TrimSpace(os.Getenv("OS_INSECURE")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("parse OS_INSECURE=%q: %w", raw, err)
		}
		insecure = value
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure, // #nosec G402 -- requested by OS_INSECURE
	}

	caCertPath := strings.TrimSpace(os.Getenv("OS_CACERT"))
	if caCertPath == "" {
		return tlsConfig, nil
	}
	certificate, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read OS_CACERT %q: %w", caCertPath, err)
	}
	certificatePool := x509.NewCertPool()
	if !certificatePool.AppendCertsFromPEM(certificate) {
		return nil, fmt.Errorf("parse OS_CACERT %q: no PEM certificates", caCertPath)
	}
	tlsConfig.RootCAs = certificatePool
	return tlsConfig, nil
}

func hasSplitDomainEnvironment() bool {
	return firstEnvironment(
		"OS_USER_DOMAIN_ID",
		"OS_USER_DOMAIN_NAME",
		"OS_PROJECT_DOMAIN_ID",
		"OS_PROJECT_DOMAIN_NAME",
	) != ""
}

func firstEnvironment(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}
