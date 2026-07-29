package cloud

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
)

func TestAuthOptionsSupportApplicationCredentials(t *testing.T) {
	clearOpenStackEnvironment(t)
	t.Setenv("OS_AUTH_URL", "https://identity.example/v3")
	t.Setenv("OS_AUTH_TYPE", "v3applicationcredential")
	t.Setenv("OS_APPLICATION_CREDENTIAL_ID", "application-id")
	t.Setenv("OS_APPLICATION_CREDENTIAL_SECRET", "application-secret")

	auth, err := authOptionsFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if auth.ApplicationCredentialID != "application-id" ||
		auth.ApplicationCredentialSecret != "application-secret" {
		t.Fatalf("application credential auth = %+v", auth)
	}
	if auth.Password != "" {
		t.Fatalf("application credential auth retained a password: %+v", auth)
	}
}

func TestAuthOptionsSupportSeparateUserAndProjectDomains(t *testing.T) {
	clearOpenStackEnvironment(t)
	t.Setenv("OS_AUTH_URL", "https://identity.example/v3")
	t.Setenv("OS_USERNAME", "demo")
	t.Setenv("OS_PASSWORD", "secret")
	t.Setenv("OS_USER_DOMAIN_NAME", "users")
	t.Setenv("OS_PROJECT_NAME", "service")
	t.Setenv("OS_PROJECT_DOMAIN_NAME", "projects")

	auth, err := authOptionsFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if auth.DomainName != "users" {
		t.Fatalf("user DomainName = %q", auth.DomainName)
	}
	if auth.Scope == nil ||
		auth.Scope.ProjectName != "service" ||
		auth.Scope.DomainName != "projects" {
		t.Fatalf("project Scope = %+v", auth.Scope)
	}
}

func TestAuthOptionsSupportStandardUserIDSpelling(t *testing.T) {
	clearOpenStackEnvironment(t)
	t.Setenv("OS_AUTH_URL", "https://identity.example/v3")
	t.Setenv("OS_USER_ID", "user-id")
	t.Setenv("OS_PASSWORD", "secret")
	t.Setenv("OS_PROJECT_ID", "project-id")

	auth, err := authOptionsFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if auth.UserID != "user-id" || auth.Scope == nil ||
		auth.Scope.ProjectID != "project-id" {
		t.Fatalf("auth = %+v", auth)
	}
}

func TestEndpointOptionsRespectOSInterface(t *testing.T) {
	clearOpenStackEnvironment(t)
	t.Setenv("OS_INTERFACE", "internal")
	t.Setenv("OS_REGION_NAME", "RegionOne")

	endpoint, err := endpointOptionsFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Availability != gophercloud.AvailabilityInternal {
		t.Fatalf("Availability = %q", endpoint.Availability)
	}
	if endpoint.Region != "RegionOne" {
		t.Fatalf("Region = %q", endpoint.Region)
	}
}

func TestTLSConfigRespectsOSInsecure(t *testing.T) {
	clearOpenStackEnvironment(t)
	t.Setenv("OS_INSECURE", "true")
	t.Setenv("OS_CACERT", "/missing/ca.pem")

	tlsConfig, err := tlsConfigFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("OS_INSECURE=true did not disable certificate verification")
	}
}

func TestTLSConfigVerifiesCertificatesByDefault(t *testing.T) {
	clearOpenStackEnvironment(t)

	tlsConfig, err := tlsConfigFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.InsecureSkipVerify {
		t.Fatal("certificate verification is disabled without OS_INSECURE=true")
	}
}

func TestTLSConfigRejectsInvalidCACert(t *testing.T) {
	clearOpenStackEnvironment(t)
	caCertPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caCertPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OS_CACERT", caCertPath)

	if _, err := tlsConfigFromEnvironment(); err == nil {
		t.Fatal("invalid OS_CACERT was accepted")
	}
}

func TestTLSConfigRejectsInvalidOSInsecure(t *testing.T) {
	clearOpenStackEnvironment(t)
	t.Setenv("OS_INSECURE", "sometimes")

	if _, err := tlsConfigFromEnvironment(); err == nil {
		t.Fatal("invalid OS_INSECURE was accepted")
	}
}

func clearOpenStackEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"OS_APPLICATION_CREDENTIAL_ID",
		"OS_APPLICATION_CREDENTIAL_NAME",
		"OS_APPLICATION_CREDENTIAL_SECRET",
		"OS_AUTH_TYPE",
		"OS_AUTH_URL",
		"OS_CACERT",
		"OS_CLOUD",
		"OS_DOMAIN_ID",
		"OS_DOMAIN_NAME",
		"OS_ENDPOINT_TYPE",
		"OS_INSECURE",
		"OS_INTERFACE",
		"OS_PASSCODE",
		"OS_PASSWORD",
		"OS_PROJECT_DOMAIN_ID",
		"OS_PROJECT_DOMAIN_NAME",
		"OS_PROJECT_ID",
		"OS_PROJECT_NAME",
		"OS_REGION_NAME",
		"OS_SYSTEM_SCOPE",
		"OS_TENANT_ID",
		"OS_TENANT_NAME",
		"OS_USER_DOMAIN_ID",
		"OS_USER_DOMAIN_NAME",
		"OS_USER_ID",
		"OS_USERID",
		"OS_USERNAME",
	} {
		t.Setenv(name, "")
	}
}
