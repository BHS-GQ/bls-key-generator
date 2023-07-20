package kyber_generator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

func getOutputDir() string {
	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}

	return filepath.Join(path, "temp")
}

func Generate(n int) string {
	var q int = Q(n)

	suite := bn256.NewSuite()
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), q, secret, suite.RandomStream()) // Private key
	pubPoly := priPoly.Commit(suite.G2().Point().Base())                     // Common public key

	currentTime := time.Now().Format("2006-01-02_15:04:05")
	keyDir := fmt.Sprintf("%d_%s", n, currentTime)
	outputDir := filepath.Join(
		getOutputDir(),
		keyDir,
	)
	os.MkdirAll(outputDir, os.ModePerm)

	// Private Keys
	for idx, x := range priPoly.Shares(n) {
		privateByte, err := x.V.MarshalBinary()
		if err != nil {
			log.Println(err)
		}
		pris := PriShare{Index: x.I, Pri: privateByte}

		priBytes, err := json.Marshal(pris)
		if err != nil {
			log.Fatal(err)
		}

		privKeyFile := filepath.Join(
			outputDir,
			fmt.Sprintf("bls-private-key%d.json", idx+1),
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

	// Public Key
	PubShares := make([]PubShare, n)
	for i, x := range pubPoly.Shares(n) {
		pubByte, err := x.V.MarshalBinary()
		if err != nil {
			log.Println(err)
		}
		pB := PubShare{Index: x.I, Pub: pubByte}
		PubShares[i] = pB
	}

	pubBytes, err := json.Marshal(PubShares)
	if err != nil {
		log.Println(err)
	}

	pubKeyFile := filepath.Join(
		outputDir,
		"bls-public-key.json",
	)
	err = ioutil.WriteFile(pubKeyFile, pubBytes, 0644)
	if err != nil {
		log.Println(err)
	}

	return outputDir
}
