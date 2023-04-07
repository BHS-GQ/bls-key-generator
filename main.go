package main

import (
	"log"
	"main/generator"
	"os"
	"strconv"
)

func main() {
	N, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Println(err)
		return
	}

	generator.Generate(N)
}
