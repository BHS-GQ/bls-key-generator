package main

import (
	"log"
	"main/fg_generator"
	"os"
	"strconv"
)

func main() {
	N, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Println(err)
		return
	}

	fg_generator.Generate(N)
}
