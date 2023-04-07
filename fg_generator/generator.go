package fg_generator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"os"
	"path/filepath"
	"time"

	fg_crypto "github.com/onflow/flow-go/crypto"
)

const thresholdSignatureTag = "random tag"

func getOutputDir() string {
	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}

	return filepath.Join(path, "temp")
}

func Generate(n int) string {
	var q int = Q(n)

	mrand.Seed(time.Now().UnixNano())
	seed := make([]byte, 16)
	_, err := mrand.Read(seed)
	if err != nil {
		log.Println("Read()", err)
	}
	skShares, pkShares, pkGroup, err := fg_crypto.BLSThresholdKeyGen(n, q, seed)
	if err != nil {
		log.Println("BLSThresholdKeyGen()", err)
	}

	currentTime := time.Now().Format("2006-01-02_15:04:05")
	keyDir := fmt.Sprintf("%d_%s", n, currentTime)
	outputDir := filepath.Join(
		getOutputDir(),
		keyDir,
	)
	os.MkdirAll(outputDir, os.ModePerm)

	for idx, sk := range skShares {
		skBytes := sk.Encode()
		pris := PriShare{Index: idx, Pri: skBytes}

		priBytes, err := json.Marshal(pris)
		if err != nil {
			log.Fatal(err)
		}

		privKeyFile := filepath.Join(
			outputDir,
			fmt.Sprintf("bls-private-key%d.json", idx),
		)

		// Write json array to file.
		_, err = os.Create(privKeyFile)
		if err != nil {
			log.Println(err)
		}
		err = ioutil.WriteFile(privKeyFile, priBytes, 0644)
		if err != nil {
			log.Println(err)
		}
	}

	pkGroupBytes := pkGroup.Encode()
	for idx, pk := range pkShares {
		pkBytes := pk.Encode()
		pubs := PubKey{Index: idx, Share: pkBytes, Group: pkGroupBytes}
		pubBytes, err := json.Marshal(pubs)
		if err != nil {
			log.Fatal(err)
		}

		privKeyFile := filepath.Join(
			outputDir,
			fmt.Sprintf("bls-public-key%d.json", idx),
		)

		// Write json array to file.
		_, err = os.Create(privKeyFile)
		if err != nil {
			log.Println(err)
		}
		err = ioutil.WriteFile(privKeyFile, pubBytes, 0644)
		if err != nil {
			log.Println(err)
		}
	}

	return outputDir
}
