package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNormalizeKeepsRelativeURL(t *testing.T) {
	input := []byte("StorePath: /nix/store/abc\nURL: nar/abc.nar\nSig: key:sig\n")

	output := string(normalize(input))

	if !strings.Contains(output, "URL: nar/abc.nar\n") {
		t.Fatalf("relative URL was rewritten: %q", output)
	}
}

func TestNormalizeRewritesAbsoluteURL(t *testing.T) {
	input := []byte("StorePath: /nix/store/abc\nURL: https://cache.nixos.org/nar/abc.nar.zst?token=1\n")

	output := string(normalize(input))

	if !strings.Contains(output, "URL: nar/abc.nar.zst\n") {
		t.Fatalf("absolute URL was not rewritten: %q", output)
	}
}

func TestNormalizeAddsTrailingNewline(t *testing.T) {
	if output := string(normalize([]byte("URL: nar/abc.nar"))); !strings.HasSuffix(output, "\n") {
		t.Fatalf("missing trailing newline: %q", output)
	}
}

func TestValidateAcceptsMatchingNarinfo(t *testing.T) {
	body := []byte(
		"StorePath: /nix/store/9l0j15jg8634hkb6d4c9y95mpxl0nhrd-jq-1.8.2-bin\n" +
			"NarHash: sha256:1y1zn2h9pza8ha96l3xrvqananbqxcgw8iirgxixmmzwd8brlhrf\n" +
			"NarSize: 35680\n",
	)

	if err := validate(body, "9l0j15jg8634hkb6d4c9y95mpxl0nhrd"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsMismatchedHash(t *testing.T) {
	body := []byte(
		"StorePath: /nix/store/00000000000000000000000000000000-jq-1.8.2-bin\n" +
			"NarHash: sha256:1y1zn2h9pza8ha96l3xrvqananbqxcgw8iirgxixmmzwd8brlhrf\n" +
			"NarSize: 35680\n",
	)

	if err := validate(body, "9l0j15jg8634hkb6d4c9y95mpxl0nhrd"); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestVerifyNarinfoAcceptsTrustedSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		t.Fatal(err)
	}

	const (
		storeDir  = "/nix/store"
		storePath = storeDir + "/9l0j15jg8634hkb6d4c9y95mpxl0nhrd-jq-1.8.2-bin"
		narHash   = "sha256:1y1zn2h9pza8ha96l3xrvqananbqxcgw8iirgxixmmzwd8brlhrf"
	)

	fingerprint := "1;" + storePath + ";" + narHash + ";35680;" + storePath
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(fingerprint)))
	key := "test-1:" + base64.StdEncoding.EncodeToString(publicKey)

	body := []byte(
		"StorePath: " + storePath + "\n" +
			"NarHash: " + narHash + "\n" +
			"NarSize: 35680\n" +
			"References: 9l0j15jg8634hkb6d4c9y95mpxl0nhrd-jq-1.8.2-bin\n" +
			"Sig: test-1:" + signature + "\n",
	)

	if err := verifyNarinfo(body, storeDir, []string{key}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyNarinfoRejectsTamperedNarinfo(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		t.Fatal(err)
	}

	const (
		storeDir  = "/nix/store"
		storePath = storeDir + "/9l0j15jg8634hkb6d4c9y95mpxl0nhrd-jq-1.8.2-bin"
		narHash   = "sha256:1y1zn2h9pza8ha96l3xrvqananbqxcgw8iirgxixmmzwd8brlhrf"
	)

	fingerprint := "1;" + storePath + ";" + narHash + ";35680;" + storePath
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(fingerprint)))
	key := "test-1:" + base64.StdEncoding.EncodeToString(publicKey)

	body := []byte(
		"StorePath: " + storePath + "\n" +
			"NarHash: " + narHash + "\n" +
			"NarSize: 99999\n" +
			"References: 9l0j15jg8634hkb6d4c9y95mpxl0nhrd-jq-1.8.2-bin\n" +
			"Sig: test-1:" + signature + "\n",
	)

	if err := verifyNarinfo(body, storeDir, []string{key}); err == nil {
		t.Fatal("expected verification failure")
	}
}
