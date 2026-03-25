//go:build integration
// +build integration

package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

const transitMount = "transit-test"

// setupTransit enables the Transit secrets engine if not already enabled
func setupTransit(t *testing.T, ctx context.Context, client *api.Client) {
	t.Helper()

	// Check if transit mount already exists
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		t.Fatalf("Failed to list mounts: %v", err)
	}

	transitMountPath := transitMount + "/"
	transitExists := false
	if _, ok := mounts[transitMountPath]; ok {
		transitExists = true
		testLogger.Info("Transit mount already exists", "mount", transitMount)
	}

	if !transitExists {
		// Enable Transit secrets engine
		if err := client.Sys().Mount(transitMount, &api.MountInput{
			Type: "transit",
		}); err != nil {
			t.Fatalf("Failed to mount transit: %v", err)
		}
		testLogger.Info("Enabled Transit secrets engine", "mount", transitMount)
	}
}

// TestIntegration_GenerateExportableKey_RSA2048 tests generating an RSA 2048-bit key
func TestIntegration_GenerateExportableKey_RSA2048(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Generate RSA-2048 key
	privateKey, publicKey, err := testBackend.GenerateExportableKey(ctx, transitMount, "rsa", 2048)
	if err != nil {
		t.Fatalf("GenerateExportableKey() failed: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Expected private key, got nil")
	}

	if publicKey == nil {
		t.Fatal("Expected public key, got nil")
	}

	// Verify it's an RSA key
	rsaPrivate, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *rsa.PrivateKey, got %T", privateKey)
	}

	rsaPublic, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Expected *rsa.PublicKey, got %T", publicKey)
	}

	// Verify key size
	if rsaPrivate.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d bits", rsaPrivate.N.BitLen())
	}

	// Verify public key matches private key
	if rsaPrivate.PublicKey.N.Cmp(rsaPublic.N) != 0 {
		t.Error("Public key doesn't match private key")
	}

	t.Logf("Generated RSA-2048 key: %d bits", rsaPrivate.N.BitLen())
}

// TestIntegration_GenerateExportableKey_RSA4096 tests generating an RSA 4096-bit key
func TestIntegration_GenerateExportableKey_RSA4096(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Generate RSA-4096 key
	privateKey, _, err := testBackend.GenerateExportableKey(ctx, transitMount, "rsa", 4096)
	if err != nil {
		t.Fatalf("GenerateExportableKey() failed: %v", err)
	}

	// Verify it's an RSA key
	rsaPrivate, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *rsa.PrivateKey, got %T", privateKey)
	}

	// Verify key size
	if rsaPrivate.N.BitLen() != 4096 {
		t.Errorf("Expected 4096-bit key, got %d bits", rsaPrivate.N.BitLen())
	}

	t.Logf("Generated RSA-4096 key: %d bits", rsaPrivate.N.BitLen())
}

// TestIntegration_GenerateExportableKey_ECDSAP256 tests generating an ECDSA P-256 key
func TestIntegration_GenerateExportableKey_ECDSAP256(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Generate ECDSA P-256 key
	privateKey, publicKey, err := testBackend.GenerateExportableKey(ctx, transitMount, "ecdsa", 256)
	if err != nil {
		t.Fatalf("GenerateExportableKey() failed: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Expected private key, got nil")
	}

	if publicKey == nil {
		t.Fatal("Expected public key, got nil")
	}

	// Verify it's an ECDSA key
	ecdsaPrivate, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", privateKey)
	}

	ecdsaPublic, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PublicKey, got %T", publicKey)
	}

	// Verify curve
	if ecdsaPrivate.Curve.Params().Name != "P-256" {
		t.Errorf("Expected P-256 curve, got %s", ecdsaPrivate.Curve.Params().Name)
	}

	// Verify public key matches private key
	if ecdsaPrivate.PublicKey.X.Cmp(ecdsaPublic.X) != 0 || ecdsaPrivate.PublicKey.Y.Cmp(ecdsaPublic.Y) != 0 {
		t.Error("Public key doesn't match private key")
	}

	t.Logf("Generated ECDSA P-256 key: curve=%s", ecdsaPrivate.Curve.Params().Name)
}

// TestIntegration_GenerateExportableKey_ECDSAP384 tests generating an ECDSA P-384 key
func TestIntegration_GenerateExportableKey_ECDSAP384(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Generate ECDSA P-384 key
	privateKey, _, err := testBackend.GenerateExportableKey(ctx, transitMount, "ecdsa", 384)
	if err != nil {
		t.Fatalf("GenerateExportableKey() failed: %v", err)
	}

	// Verify it's an ECDSA key
	ecdsaPrivate, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", privateKey)
	}

	// Verify curve
	if ecdsaPrivate.Curve.Params().Name != "P-384" {
		t.Errorf("Expected P-384 curve, got %s", ecdsaPrivate.Curve.Params().Name)
	}

	t.Logf("Generated ECDSA P-384 key: curve=%s", ecdsaPrivate.Curve.Params().Name)
}

// TestIntegration_GenerateExportableKey_ECDSAP521 tests generating an ECDSA P-521 key
func TestIntegration_GenerateExportableKey_ECDSAP521(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Generate ECDSA P-521 key
	privateKey, _, err := testBackend.GenerateExportableKey(ctx, transitMount, "ecdsa", 521)
	if err != nil {
		t.Fatalf("GenerateExportableKey() failed: %v", err)
	}

	// Verify it's an ECDSA key
	ecdsaPrivate, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", privateKey)
	}

	// Verify curve
	if ecdsaPrivate.Curve.Params().Name != "P-521" {
		t.Errorf("Expected P-521 curve, got %s", ecdsaPrivate.Curve.Params().Name)
	}

	t.Logf("Generated ECDSA P-521 key: curve=%s", ecdsaPrivate.Curve.Params().Name)
}

// TestIntegration_GenerateExportableKey_InvalidKeyType tests error handling for invalid key type
func TestIntegration_GenerateExportableKey_InvalidKeyType(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Try to generate key with invalid type
	_, _, err = testBackend.GenerateExportableKey(ctx, transitMount, "invalid-type", 2048)
	if err == nil {
		t.Fatal("Expected error for invalid key type, got nil")
	}

	t.Logf("Expected error for invalid key type: %v", err)
}

// TestIntegration_GenerateExportableKey_InvalidKeySize tests error handling for invalid key size
func TestIntegration_GenerateExportableKey_InvalidKeySize(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Try to generate RSA key with invalid size
	_, _, err = testBackend.GenerateExportableKey(ctx, transitMount, "rsa", 1024)
	if err == nil {
		t.Fatal("Expected error for invalid RSA key size, got nil")
	}

	t.Logf("Expected error for invalid key size: %v", err)
}

// TestIntegration_GenerateExportableKey_InvalidMount tests error handling for invalid mount
func TestIntegration_GenerateExportableKey_InvalidMount(t *testing.T) {
	ctx := context.Background()

	// Try to generate key with non-existent mount
	_, _, err := testBackend.GenerateExportableKey(ctx, "nonexistent-transit", "rsa", 2048)
	if err == nil {
		t.Fatal("Expected error for invalid mount, got nil")
	}

	t.Logf("Expected error for invalid mount: %v", err)
}

// TestIntegration_GenerateExportableKey_AllRSASizes tests all supported RSA key sizes
func TestIntegration_GenerateExportableKey_AllRSASizes(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Test all supported RSA sizes
	sizes := []int{2048, 3072, 4096}

	for _, size := range sizes {
		t.Run("RSA"+string(rune(size)), func(t *testing.T) {
			privateKey, publicKey, err := testBackend.GenerateExportableKey(ctx, transitMount, "rsa", size)
			if err != nil {
				t.Fatalf("GenerateExportableKey(rsa, %d) failed: %v", size, err)
			}

			rsaPrivate, ok := privateKey.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("Expected *rsa.PrivateKey, got %T", privateKey)
			}

			if rsaPrivate.N.BitLen() != size {
				t.Errorf("Expected %d-bit key, got %d bits", size, rsaPrivate.N.BitLen())
			}

			// Verify public key
			rsaPublic, ok := publicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("Expected *rsa.PublicKey, got %T", publicKey)
			}

			if rsaPrivate.PublicKey.N.Cmp(rsaPublic.N) != 0 {
				t.Error("Public key doesn't match private key")
			}

			t.Logf("RSA-%d key generated successfully", size)
		})
	}
}

// TestIntegration_GenerateExportableKey_AllECDSACurves tests all supported ECDSA curves
func TestIntegration_GenerateExportableKey_AllECDSACurves(t *testing.T) {
	ctx := context.Background()

	// Setup Transit
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	setupTransit(t, ctx, client)

	// Test all supported ECDSA curves
	curves := []struct {
		bits int
		name string
	}{
		{256, "P-256"},
		{384, "P-384"},
		{521, "P-521"},
	}

	for _, curve := range curves {
		t.Run("ECDSA-"+curve.name, func(t *testing.T) {
			privateKey, publicKey, err := testBackend.GenerateExportableKey(ctx, transitMount, "ecdsa", curve.bits)
			if err != nil {
				t.Fatalf("GenerateExportableKey(ecdsa, %d) failed: %v", curve.bits, err)
			}

			ecdsaPrivate, ok := privateKey.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("Expected *ecdsa.PrivateKey, got %T", privateKey)
			}

			if ecdsaPrivate.Curve.Params().Name != curve.name {
				t.Errorf("Expected %s curve, got %s", curve.name, ecdsaPrivate.Curve.Params().Name)
			}

			// Verify public key
			ecdsaPublic, ok := publicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("Expected *ecdsa.PublicKey, got %T", publicKey)
			}

			if ecdsaPrivate.PublicKey.X.Cmp(ecdsaPublic.X) != 0 || ecdsaPrivate.PublicKey.Y.Cmp(ecdsaPublic.Y) != 0 {
				t.Error("Public key doesn't match private key")
			}

			t.Logf("ECDSA %s key generated successfully", curve.name)
		})
	}
}

// TestIntegration_Client_GenerateExportableKey tests key generation through Client wrapper
func TestIntegration_Client_GenerateExportableKey(t *testing.T) {
	ctx := context.Background()

	// Create a client
	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	// Setup Transit using API client
	apiClient := client.GetAPIClient()
	setupTransit(t, ctx, apiClient)

	// Generate key through Client wrapper
	privateKey, publicKey, err := client.GenerateExportableKey(ctx, transitMount, "rsa", 2048)
	if err != nil {
		t.Fatalf("Client.GenerateExportableKey() failed: %v", err)
	}

	if privateKey == nil || publicKey == nil {
		t.Fatal("Expected keys, got nil")
	}

	rsaPrivate, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *rsa.PrivateKey, got %T", privateKey)
	}

	if rsaPrivate.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d bits", rsaPrivate.N.BitLen())
	}

	t.Logf("Client.GenerateExportableKey() successful: %d-bit RSA key", rsaPrivate.N.BitLen())
}
