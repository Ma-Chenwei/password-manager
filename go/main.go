package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	fmt.Println("======================================")
	fmt.Println(" Password Manager")
	fmt.Println(" Go Backend")
	fmt.Println("======================================")
	fmt.Println()
	fmt.Println("Listening:")
	fmt.Println("http://127.0.0.1:1107")
	fmt.Println()

	if err := InitApplication(); err != nil {
		log.Fatal(err)
	}

	go func() {
		if err := StartWebServer(); err != nil {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(
		sig,
		os.Interrupt,
		syscall.SIGTERM,
	)

	<-sig

	fmt.Println()
	fmt.Println("Password Manager stopped.")
}
