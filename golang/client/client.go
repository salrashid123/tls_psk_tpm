package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/pion/dtls/v2"
)

const ()

var ()

const ()

func main() {

	flag.Parse()
	alice := "6368616e676520746869732070617373776f726420746f206120736563726574"

	psk, err := hex.DecodeString(alice)
	if err != nil {
		log.Fatal(err)
	}

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}

	config := &dtls.Config{
		PSK: func(hint []byte, client [28]byte, server [28]byte) ([]byte, error) {
			fmt.Printf("Client's hint: %s \n", hint)
			fmt.Printf("client: %s \n", hex.EncodeToString(client[:]))
			fmt.Printf("server: %s \n", hex.EncodeToString(server[:]))

			h := append([]byte("pre master secret"), client[:]...)
			data := append(h, server[:]...)

			hmac := hmac.New(sha256.New, psk)
			hmac.Write([]byte(data))
			r := hmac.Sum(nil)
			fmt.Printf("calculated PSK: %s\n", hex.EncodeToString(r))
			return r, nil
		},
		PSKIdentityHint: []byte("Client1"),
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256}, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
		//ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, config)
	if err != nil {
		fmt.Printf("Error dialing : %v\n", err.Error())
		os.Exit(1)
	}

	_, err = dtlsConn.Write([]byte("This is a UDP message"))
	if err != nil {
		fmt.Printf("Write data failed: %v\n", err.Error())
		os.Exit(1)
	}

	received := make([]byte, 1024)
	_, err = dtlsConn.Read(received)
	if err != nil {
		fmt.Printf("Read data failed: %v\n", err.Error())
		os.Exit(1)
	}

	fmt.Println(string(received))

}
