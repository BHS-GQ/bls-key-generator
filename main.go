package main

import (
	"log"
	"main/kyber_generator"
	"os"
	"strconv"
)

func main() {
	N, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Println(err)
		return
	}

	kyber_generator.Generate(N)
}
