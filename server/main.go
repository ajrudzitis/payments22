package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"

	_ "github.com/stripe/stripe-go/v78"
	"golang.org/x/crypto/ssh"
)

func main() {
	// read a bind address and port from the command line
	// if none are provided, use the default values
	bindAddr := "localhost"
	port := "8080"
	// read from the command line
	if len(os.Args) > 1 {
		bindAddr = os.Args[1]
	}
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	createAPIServer(bindAddr, port)

}

// createAPIServer will create a new HTTP server to receive requests
// to create HTTP servers
func createAPIServer(bindAddr string, port string) {

	http.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		// parse the amount from the request url param
		amountStr := r.URL.Query().Get("amount")
		if amountStr == "" {
			http.Error(w, "missing amount", http.StatusBadRequest)
			return
		}

		connectStr, err := createPaymentSSHServer(amountStr, bindAddr)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create payment server: %v", err), http.StatusInternalServerError)
			return
		}

		// return a 200 response
		w.Write([]byte(fmt.Sprintf("%s\r\n", connectStr)))
	})

	// generate a random tls certificate and key
	http.ListenAndServe(fmt.Sprintf("%s:%s", bindAddr, port), nil)
}

// createPaymentSSHServer server creates a new SSH server on a random port, with a random
// user and password, to accept payment details. It returns a connection string if sucessful,
// or an error if not.
func createPaymentSSHServer(amount string, bindAddr string) (string, error) {
	// generate a random user name of the form "payme" suffixed by six random digits
	username := fmt.Sprintf("payme%06d", mathrand.Intn(1000000))
	// generate a random password made up of 12 random characters
	// password := make([]byte, 12)
	// for i := range password {
	// 	password[i] = byte(mathrand.Intn(26) + 65)
	//}

	// get the current host name
	//host, err := os.Hostname()
	//if err != nil {
	//	return "", fmt.Errorf("failed to get hostname: %w", err)
	//}

	// generate a random ecdsa key pair for the server
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate server key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// create a server config
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(signer)

	// create a listener on a random port
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", bindAddr))
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
	}

	// get the port from the listener
	_, port, err := net.SplitHostPort(listener.Addr().String())

	// create connection string for the server that can be used to ssh to the listerner
	// with the given username and password
	connStr := fmt.Sprintf("ssh %s@%s -p %s", username, bindAddr, port)

	// create the server in a goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf("failed to accept connection: %v\n", err)
				continue
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					fmt.Printf("failed to handshake: %v\n", err)
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						fmt.Printf("could not accept channel: %v\n", err)
						return
					}
					go func() {
						for req := range requests {
							ok := false
							switch req.Type {
							case "shell":
								ok = true
							case "pty-req":
								ok = true
							}
							req.Reply(ok, nil)
						}
					}()
					acceptPayment(amount, channel)
					channel.Close()
					return
				}
			}()
		}
	}()

	return connStr, nil
}

func acceptPayment(amount string, channel ssh.Channel) {
	_, err := channel.Write([]byte(fmt.Sprintf("Welcome to the payment server\r\nYou owe: $%s\r\nEnter a card number: ", amount)))
	if err != nil {
		fmt.Printf("failed to write to channel: %v\n", err)
		return
	}

	// read the payment details from the channel
	// and process the payment
	cardNumer, err := readNextLine(channel)
	if err != nil {
		fmt.Printf("failed to read card number: %v\n", err)
		return
	}
	fmt.Printf("card number: %s\n", cardNumer)

	_, err = channel.Write([]byte("\r\nThank you for your payment\r\n"))
	if err != nil {
		fmt.Printf("failed to write to channel: %v\n", err)
		return
	}
}

func readNextLine(channel ssh.Channel) (string, error) {
	var buf bytes.Buffer
	for {
		b := make([]byte, 1)
		_, err := channel.Read(b)
		if err != nil {
			return "", fmt.Errorf("failed to read from channel: %w", err)
		}
		buf.Write(b)
		if b[0] == '\r' {
			break
		}
		channel.Write(b)
	}
	return buf.String(), nil
}
