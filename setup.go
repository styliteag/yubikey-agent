// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/term"
)

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func init() {
	if Version != "" {
		return
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		Version = buildInfo.Main.Version
		return
	}
	Version = "(unknown version)"
}

func connectForSetup(cardSerial uint32) *piv.YubiKey {
	cardNr := 999

	if cardSerial == 0 {
		// Use First Card
		cardNr = 0
	}

	cards, err := piv.Cards()
	if err != nil {
		log.Fatalln("Failed to enumerate tokens:", err)
	}
	if len(cards) == 0 {
		log.Fatalln("No YubiKeys detected!")
	}
	// Support multiple YubiKeys.
	for i, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			yk, err := piv.Open(card)
			if err != nil {
				log.Printf("unable to open yubikey: %s\n", cards)
				continue
			}
			serial, err := yk.Serial()
			if err != nil {
				log.Printf("unable to get yubikey serial number: %v\n", serial)
				continue
			}
			log.Printf("Card: %v, SN: %v, Name: %v\n", i, serial, card)
			if serial == cardSerial {
				cardNr = i
				log.Printf("Found Card: %v, SN: %v\n", cardNr, serial)
			}
			yk.Close()

		}
	}
	if cardNr == 999 {
		// No Card Found
		log.Fatalf("No Card with Serial: %v\n", cardSerial)
	}
	if cardNr+1 > len(cards) {
		log.Fatalf("NO Card: %v\n", cardNr)
	}
	log.Printf("Connecting to Card %v", cardNr)
	yk, err := piv.Open(cards[cardNr])
	if err != nil {
		log.Fatalln("Failed to connect to the YubiKey:", err)
	}
	return yk
}

func runReset(yk *piv.YubiKey) {
	fmt.Println("Resetting YubiKey PIV applet...")
	if err := yk.Reset(); err != nil {
		log.Fatalln("Failed to reset YubiKey:", err)
	}
}

func runSetup(yk *piv.YubiKey, touchPolicy piv.TouchPolicy, alg piv.Algorithm) {
	if _, err := yk.Certificate(piv.SlotAuthentication); err == nil {
		log.Println("‼️  This YubiKey looks already setup")
		log.Println("")
		pub, err := getPublicKey(yk, piv.SlotAuthentication)
		if err != nil {
			log.Fatalln("Failed to get public key:", err)
		}
		log.Println("🔑 Here's your existing SSH public key:")
		os.Stdout.Write(ssh.MarshalAuthorizedKey(pub))
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	} else if !errors.Is(err, piv.ErrNotFound) {
		log.Fatalln("Failed to access authentication slot:", err)
	}

	fmt.Println("🔐 The PIN is up to 8 numbers, letters, or symbols. Not just numbers!")
	fmt.Println("❌ The key will be lost if the PIN and PUK are locked after 3 incorrect tries.")
	fmt.Println("")
	fmt.Print("Choose a new PIN/PUK: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) == 0 || len(pin) > 8 {
		log.Fatalln("The PIN needs to be 1-8 characters.")
	}
	fmt.Print("Repeat PIN/PUK: ")
	repeat, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	} else if !bytes.Equal(repeat, pin) {
		log.Fatalln("PINs don't match!")
	}

	fmt.Println("")
	fmt.Println("🧪 Reticulating splines...")

	var key [24]byte
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatal(err)
	}
	if err := yk.SetManagementKey(piv.DefaultManagementKey, key); err != nil {
		log.Println("‼️  The default Management Key did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetMetadata(key, &piv.Metadata{
		ManagementKey: &key,
	}); err != nil {
		log.Fatalln("Failed to store the Management Key on the device:", err)
	}
	if err := yk.SetPIN(piv.DefaultPIN, string(pin)); err != nil {
		log.Println("‼️  The default PIN did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetPUK(piv.DefaultPUK, string(pin)); err != nil {
		log.Println("‼️  The default PUK did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}

	pub, err := yk.GenerateKey(key, piv.SlotAuthentication, piv.Key{
		Algorithm:   alg,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: touchPolicy,
	})
	if err != nil {
		log.Fatalln("Failed to generate key:", err)
	}

	var priv crypto.Signer
	if alg == piv.AlgorithmEC256 {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if alg == piv.AlgorithmEC384 {
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	if alg == piv.AlgorithmRSA1024 {
		priv, err = rsa.GenerateKey(rand.Reader, 1024)
	}
	if alg == piv.AlgorithmRSA2048 {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if alg == piv.AlgorithmEd25519 {
		// FIXME
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}

	if err != nil {
		log.Fatalln("Failed to generate parent key:", err)
	}
	parent := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"yubikey-agent"},
			OrganizationalUnit: []string{Version},
		},
		PublicKey: priv.Public(),
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "SSH key",
		},
		NotAfter:     time.Now().AddDate(42, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: randomSerialNumber(),
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		log.Fatalln("Failed to generate certificate:", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalln("Failed to parse certificate:", err)
	}
	if err := yk.SetCertificate(key, piv.SlotAuthentication, cert); err != nil {
		log.Fatalln("Failed to store certificate:", err)
	}

	sshKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		log.Fatalln("Failed to generate public key:", err)
	}

	fmt.Println("")
	fmt.Println("✅ Done! This YubiKey is secured and ready to go.")
	fmt.Println("🤏 When the YubiKey blinks, touch it to authorize the login.")
	fmt.Println("")
	fmt.Println("🔑 Here's your new shiny SSH public key:")
	os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))
	fmt.Println("")
	fmt.Println("Next steps: ensure yubikey-agent is running via launchd/systemd/...,")
	fmt.Println(`set the SSH_AUTH_SOCK environment variable, and test with "ssh-add -L"`)
	fmt.Println("")
	fmt.Println("💭 Remember: everything breaks, have a backup plan for when this YubiKey does.")
}

func getManagementKey(yk *piv.YubiKey) {
	fmt.Print("Enter PIN: ")
	pin, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	meta, err := yk.Metadata(string(pin))
	if err != nil {
		log.Fatalln("Failed to get key metadata: ", err)
	}

	fmt.Println(hex.EncodeToString(meta.ManagementKey[:]))
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	return serialNumber
}
