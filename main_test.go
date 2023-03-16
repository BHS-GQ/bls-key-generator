package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"main/keys"
	"path/filepath"
	"strconv"
	"testing"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

// Decode public shares from pub-key.conf file...
func DecodePubKey(suite *bn256.Suite, outputDir string, n int) *share.PubPoly {
	var err error

	pubKeyFile := filepath.Join(outputDir, "blsPubKey.json")
	pubKeyBytes, err := ioutil.ReadFile(pubKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	var data []keys.PubShare
	err = json.Unmarshal(pubKeyBytes, &data)
	if err != nil {
		log.Fatal(err)
	}

	dePubShares := make([]*share.PubShare, n)
	for i, d := range data {
		point := suite.G2().Point()
		dePubShares[i] = &share.PubShare{}
		dePubShares[i].I = d.Index
		err = point.UnmarshalBinary(d.Pub)
		if err != nil {
			log.Fatal(err)
		}
		dePubShares[i].V = point
	}

	// Recover public key
	t := Q(n)
	pubKey, err := share.RecoverPubPoly(suite.G2(), dePubShares, t, n)
	if err != nil {
		log.Fatal(err)
	}
	return pubKey
}

func DecodePubShare(suite *bn256.Suite, n, t int) *share.PubPoly {
	// Read public keys from file.
	plan, _ := ioutil.ReadFile("/home/derick/eth1/keygen/temp/" + strconv.Itoa(n) + "/public_key.conf")
	var data []keys.PubShare
	err := json.Unmarshal(plan, &data)
	if err != nil {
		log.Fatal(err)
	}

	dePubShares := make([]*share.PubShare, n)

	for i, d := range data {
		point := suite.G2().Point()
		var err error
		dePubShares[i] = &share.PubShare{}
		dePubShares[i].I = d.Index
		err = point.UnmarshalBinary(d.Pub)
		if err != nil {
			log.Fatal(err)
		}
		dePubShares[i].V = point
	}
	// Recover public key.
	pubKey, err := share.RecoverPubPoly(suite.G2(), dePubShares, t, n)
	if err != nil {
		log.Fatal(err)
	}
	return pubKey
}

func TestBLSKeyGen(t *testing.T) {
	n := 50
	f := F(n)
	q := Q(n)
	outputDir := generate(n)

}
