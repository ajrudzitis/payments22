package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	_ "github.com/stripe/stripe-go/v78"
	"golang.org/x/crypto/ssh"
)

var (
	// payment session timeout
	paymentTimeout = time.Duration(10 * time.Minute)
)

func main() {
	// read a bind address and port from the command line
	// if none are provided, use the default values
	bindAddr := "127.0.0.1"
	port := "8080"
	// externAddr will be the address that the client will use to connect to the server
	externAddr := bindAddr
	// read from the command line
	if len(os.Args) > 1 {
		externAddr = os.Args[1]
	}
	if len(os.Args) > 2 {
		bindAddr = os.Args[2]
	}
	if len(os.Args) > 3 {
		port = os.Args[3]
	}

	bindIP := net.ParseIP(bindAddr)
	if bindIP == nil {
		fmt.Printf("invalid bind address: %s\n", bindAddr)
		os.Exit(1)
	}

	fmt.Printf("Starting server on %s:%s\n", bindAddr, port)

	// create the API server
	createAPIServer(externAddr, port, bindIP)

}

// createAPIServer will create a new HTTP server to receive requests
// to create HTTP servers
func createAPIServer(externAddr, port string, bindIP net.IP) {

	http.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		// parse the amount from the request url param
		amountStr := r.URL.Query().Get("amount")
		if amountStr == "" {
			http.Error(w, "missing amount", http.StatusBadRequest)
			return
		}

		connectStr, err := createPaymentSSHServer(amountStr, externAddr, bindIP)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create payment server: %v", err), http.StatusInternalServerError)
			return
		}

		// return a 200 response
		w.Write([]byte(fmt.Sprintf("%s\r\n", connectStr)))
	})

	// generate a random tls certificate and key
	http.ListenAndServe(fmt.Sprintf("%s:%s", bindIP, port), nil)
}

// createPaymentSSHServer server creates a new SSH server on a random port, with a random
// user and password, to accept payment details. It returns a connection string if sucessful,
// or an error if not.
func createPaymentSSHServer(amount, externAddr string, bindIP net.IP) (string, error) {
	// generate a random user name of the form "payme" suffixed by six random digits
	username := fmt.Sprintf("payme%06d", mathrand.Intn(1000000))

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
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bindIP, Port: 0})
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
	}

	// get the port from the listener
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return "", fmt.Errorf("failed to get port: %w", err)
	}

	// create connection string for the server that can be used to ssh to the listerner
	// with the given username and password
	connStr := fmt.Sprintf("ssh %s@%s -p %s", username, externAddr, port)

	// TODO: put the response in a struct
	// TODO: add the server key fingerprint to the response

	// create the server in a goroutine
	go func() {
		// TODO: create from a parent context in main
		ctx, cancelFn := context.WithCancel(context.Background())

		select {
		case <-time.After(paymentTimeout):

		case _ = <-runPaymentService(ctx, *listener, config, amount):
			//TODO : log any error in the result
		}
		cancelFn()
	}()

	return connStr, nil
}

type paymentResult struct {
	err error
}

func runPaymentService(ctx context.Context, listener net.TCPListener, config *ssh.ServerConfig, amount string) <-chan paymentResult {
	done := make(chan paymentResult)

	go func() {
		// create a wait group to track sessions in flight
		wg := sync.WaitGroup{}

		connectionResult := make(chan paymentResult)
		defer close(done)
		defer close(connectionResult)
		defer func() { _ = listener.Close() }()

	Loop:
		for {
			// do not continue if the context has been cancelled
			select {
			case <-ctx.Done():
				break Loop
			case result := <-connectionResult:
				// decrement the wait group
				wg.Done()
				if result.err != nil {
					done <- paymentResult{err: fmt.Errorf("failed to accept connection: %w", result.err)}
					break Loop
				}
			default:
				// accept more connections
			}

			// set a deadline for the listener to accept a connection
			listener.SetDeadline(time.Now().Add(5 * time.Second))
			// accept a connection
			conn, err := listener.Accept()
			if err != nil {
				// if the error is due to a timeout, continue to the next iteration
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				done <- paymentResult{err: fmt.Errorf("failed to accept connection: %w", err)}
				return
			}

			wg.Add(1)
			go handleConnection(ctx, conn, config, amount, connectionResult)
		}
		wg.Wait()
	}()
	return done
}

func handleConnection(ctx context.Context, conn net.Conn, config *ssh.ServerConfig, amount string, connectionResult chan<- paymentResult) {
	// handle the connection
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		fmt.Printf("failed to handshake: %v\n", err)
		return
	}

	// we can disregard basic requests
	go ssh.DiscardRequests(reqs)

	// handle channel requests
	for newChannel := range chans {

		// only accept session channels
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		// accept the channel
		channel, requests, err := newChannel.Accept()
		if err != nil {
			fmt.Printf("could not accept channel: %v\n", err)
			return
		}

		// handle requests on the channel
		go func() {
			// we're okay with this being a shell or pty request
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
		// TODO: clean up this code
		acceptPaymentScript(amount, channel)
		// send the result
		connectionResult <- paymentResult{err: nil}
		// close the channel
		channel.Close()
	}
	fmt.Println("connection close")
	// wait for shutdown signal
}

func acceptPaymentScript(amount string, channel ssh.Channel) {
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
