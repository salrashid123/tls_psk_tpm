package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"time"

	//"net/http/httputil"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	dtls "github.com/pion/dtls/v2"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in      = flag.String("in", "../keys/private.pem", "privateKey File")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

var ()

const ()

func main() {

	flag.Parse()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &dtls.Config{

		PSK: func(hint []byte, server [28]byte, client [28]byte) ([]byte, error) {
			fmt.Printf("Client's hint: %s \n", hint)

			fmt.Printf("server: %s \n", hex.EncodeToString(server[:]))
			fmt.Printf("client: %s \n", hex.EncodeToString(client[:]))

			h := append([]byte("pre master secret"), client[:]...)
			data := append(h, server[:]...)

			c, err := os.ReadFile(*in)
			if err != nil {
				log.Fatalf("can't load keys %q: %v", *tpmPath, err)
			}
			key, err := keyfile.Decode(c)
			if err != nil {
				log.Fatalf("can't decode keys %q: %v", *tpmPath, err)
			}

			rwc, err := openTPM(*tpmPath)
			if err != nil {
				log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
			}
			defer func() {
				rwc.Close()
			}()

			rwr := transport.FromReadWriter(rwc)
			// specify its parent directly
			primaryKey, err := tpm2.CreatePrimary{
				PrimaryHandle: key.Parent,
				InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr)
			if err != nil {
				log.Fatalf("can't create primary %q: %v", *tpmPath, err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			hmacKey, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: primaryKey.ObjectHandle,
					Name:   tpm2.TPM2BName(primaryKey.Name),
					Auth:   tpm2.PasswordAuth([]byte("")),
				},
				InPublic:  key.Pubkey,
				InPrivate: key.Privkey,
			}.Execute(rwr)
			if err != nil {
				log.Fatalf("can't hmac %q: %v", *tpmPath, err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: hmacKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			objAuth := &tpm2.TPM2BAuth{
				Buffer: nil,
			}
			psk, err := tpmhmac(rwr, data, hmacKey.ObjectHandle, hmacKey.Name, *objAuth)
			if err != nil {
				log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
			}

			flushContextPrimaryCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextPrimaryCmd.Execute(rwr)

			flushContextHMACCmd := tpm2.FlushContext{
				FlushHandle: hmacKey.ObjectHandle,
			}
			_, _ = flushContextHMACCmd.Execute(rwr)

			fmt.Printf("calculated PSK: %s\n", hex.EncodeToString(psk))
			return psk, nil
		},
		PSKIdentityHint:      []byte("Client1"),
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256}, //TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Second)
		},
	}

	l, err := dtls.Listen("udp", addr, config)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	fmt.Println("Starting dtls server")
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			// Echo all incoming data.
			io.Copy(c, c)
			// Shut down the connection.
			c.Close()
		}(conn)
	}

}

const (
	maxInputBuffer = 1024
)

var ()

func tpmhmac(rwr transport.TPM, data []byte, objHandle tpm2.TPMHandle, objName tpm2.TPM2BName, objAuth tpm2.TPM2BAuth) ([]byte, error) {

	sas, sasCloser, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(objAuth.Buffer))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = sasCloser()
	}()

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: sas.Handle(),
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: objHandle,
			Name:   objName,
			Auth:   sas,
		},
		Auth:    objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   objName,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}

		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}

func decodeHex(h string) []byte {
	data, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return data
}
