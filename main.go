// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

var cardSerial uint32

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of yubikey-agent:\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -setup [-cardserial=0123456] [-touch-policy=always|cached|never] [-pin-policy=always|once|never] [-alg=RS2048|RSA1024|EC256|EC384|Ed25519] [-generate-key-on-computer-insecurely]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tGenerate a new SSH key on the attached YubiKey.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -l PATH [-cardserial=0123456]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tRun the agent, listening on the UNIX socket at PATH.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -get-management-key [-cardserial=0123456]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\tGet the (pin-protected) management key.")
		fmt.Fprintf(os.Stderr, "\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	cardFlag := flag.Uint("cardserial", 0, "Card: Slot of the Yubikey, if multiple Cards are connected")
	algFlag := flag.String("alg", "RSA2048", "setup: Choose Key Type")
	resetFlag := flag.Bool("really-delete-all-piv-keys", false, "setup: reset the PIV applet")
	generateKeyInsecurelyFlag := flag.Bool("generate-key-on-computer-insecurely", false, "setup: generate the key on the computer instead on the hardware token, this allows creating a copy of the private key but also exposes it to exfiltration and manipulation")
	setupFlag := flag.Bool("setup", false, "setup: configure a new YubiKey")
	touchFlag := flag.String("touch-policy", "always", "setup: set the touch policy (always,cached,never)")
	pinFlag := flag.String("pin-policy", "once", "setup: set the touch policy (always,once,never)")
	getManagementFlag := flag.Bool("get-management-key", false, "Get the (pin protected) management key")
	flag.Parse()

	cardSerial = uint32(*cardFlag)

	touchPolicy := map[string]piv.TouchPolicy{
		"always": piv.TouchPolicyAlways,
		"cached": piv.TouchPolicyCached,
		"never":  piv.TouchPolicyNever,
	}[*touchFlag]

	pinPolicy := map[string]piv.PINPolicy{
		"always": piv.PINPolicyAlways,
		"once":   piv.PINPolicyOnce,
		"never":  piv.PINPolicyNever,
	}[*pinFlag]

	alg := map[string]piv.Algorithm{
		"EC256":   piv.AlgorithmEC256,
		"EC384":   piv.AlgorithmEC384,
		"RSA1024": piv.AlgorithmRSA1024,
		"RSA2048": piv.AlgorithmRSA2048,
		"Ed25519": piv.AlgorithmEd25519,
	}[*algFlag]

	if flag.NArg() > 0 || touchPolicy == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *setupFlag {
		log.SetFlags(0)
		yk := connectForSetup(cardSerial)
		if *resetFlag {
			runReset(yk)
		}
		runSetup(yk, touchPolicy, pinPolicy, alg, *generateKeyInsecurelyFlag)
	} else if *getManagementFlag {
		getManagementKey(connectForSetup(cardSerial))
	} else {
		if *socketPath == "" {
			flag.Usage()
			os.Exit(1)
		}
		runAgent(*socketPath)
	}
}

func runAgent(socketPath string) {
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: yubikey-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd or systemd services.")
	}

	a := &Agent{}

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0777); err != nil {
		log.Fatalln("Failed to create UNIX socket folder:", err)
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(c)
	}
}

type Agent struct {
	mu     sync.Mutex
	yk     *piv.YubiKey
	serial uint32

	// touchNotification is armed by Sign to show a notification if waiting for
	// more than a few seconds for the touch operation. It is paused and reset
	// by getPIN so it won't fire while waiting for the PIN.
	touchNotification *time.Timer
}

var _ agent.ExtendedAgent = &Agent{}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
}

func healthy(yk *piv.YubiKey) bool {
	// We can't use Serial because it locks the session on older firmwares, and
	// can't use Retries because it fails when the session is unlocked.
	_, err := yk.AttestationCertificate()
	return err == nil
}

func (a *Agent) ensureYK() error {
	if a.yk == nil || !healthy(a.yk) {
		if a.yk != nil {
			log.Println("Reconnecting to the YubiKey...")
			a.yk.Close()
		} else {
			log.Println("Connecting to the YubiKey...")
		}
		yk, err := a.connectToYK()
		if err != nil {
			return err
		}
		a.yk = yk
	}
	serial, err := a.yk.Serial()
	if err != nil {
		log.Printf("unable to get yubikey serial number: %v\n", serial)
		return err
	}
	//log.Printf("Serial: %v, Looking for %v\n", serial, cardSerial)
	if cardSerial != 0 && serial != cardSerial {
		log.Printf("Serial does not match, returning Err\n")
		a.yk.Close()
		return err //log.Printf("Found Card: %v, SN: %v\n", cardNr, serial)
	}
	return nil
}

func (a *Agent) connectToYK() (*piv.YubiKey, error) {
	cardNr := 999

	if cardSerial == 0 {
		// Use First Card
		cardNr = 0
	}

	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	// support multiple YubiKeys.
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
				//log.Printf("Found Card: %v, SN: %v\n", cardNr, serial)
			}
			yk.Close()
		}
	}
	if cardNr == 999 {
		// No Card Found
		log.Printf("No Card with Serial: %v\n", cardSerial)
	}
	if cardNr+1 > len(cards) {
		return nil, fmt.Errorf("Card %v not Found", cardSerial)
	}
	//log.Printf("Connecting to Card %v", cardNr)

	yk, err := piv.Open(cards[cardNr])
	if err != nil {
		return nil, err
	}
	// Cache the serial number locally because requesting it on older firmwares
	// requires switching application, which drops the PIN cache.
	a.serial, _ = yk.Serial()
	return yk, nil
}

func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.yk != nil {
		log.Println("Received SIGHUP, dropping YubiKey transaction...")
		err := a.yk.Close()
		a.yk = nil
		return err
	}
	return nil
}

func (a *Agent) getPIN() (string, error) {
	if a.touchNotification != nil && a.touchNotification.Stop() {
		defer a.touchNotification.Reset(5 * time.Second)
	}
	r, _ := a.yk.Retries()
	return getPIN(a.serial, r)
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	pk, err := getPublicKey(a.yk, piv.SlotAuthentication)
	if err != nil {
		return nil, err
	}
	return []*agent.Key{{
		Format:  pk.Type(),
		Blob:    pk.Marshal(),
		Comment: fmt.Sprintf("YubiKey #%d PIV Slot 9a", a.serial),
	}}, nil
}

func getPublicKey(yk *piv.YubiKey, slot piv.Slot) (ssh.PublicKey, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case ed25519.PublicKey:
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", cert.PublicKey)
	}
	pk, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}
	return pk, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	return a.signers()
}

func (a *Agent) signers() ([]ssh.Signer, error) {
	pk, err := getPublicKey(a.yk, piv.SlotAuthentication)
	if err != nil {
		return nil, err
	}
	priv, err := a.yk.PrivateKey(
		piv.SlotAuthentication,
		pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
		// We need to specify PINPolicy manually here. If we don't, then it'll
		// be tried to be inferred from the certificate atestation and that
		// will fail if the key has been generated insecurely on the computer
		// (there's a -setup switch for that) instead of on the hardware
		// device.
		piv.KeyAuth{PINPrompt: a.getPIN, PINPolicy: piv.PINPolicyOnce},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare private key: %w", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	return []ssh.Signer{s}, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	signers, err := a.signers()
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a.touchNotification = time.NewTimer(5 * time.Second)
		go func() {
			select {
			case <-a.touchNotification.C:
			case <-ctx.Done():
				a.touchNotification.Stop()
				return
			}
			showNotification("Waiting for YubiKey touch...")
		}()

		alg := key.Type()
		switch {
		case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha256 != 0:
			alg = ssh.SigAlgoRSASHA2256
		case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha512 != 0:
			alg = ssh.SigAlgoRSASHA2512
		}
		// TODO: maybe retry if the PIN is not correct?
		return s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
	}
	return nil, fmt.Errorf("no private keys match the requested public key")
}

func showNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
	case "linux":
		exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
	}
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var ErrOperationUnsupported = errors.New("operation unsupported")

func (a *Agent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) RemoveAll() error {
	return ErrOperationUnsupported
}
func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}
