package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"main/keys"
	"path/filepath"
	"testing"
	"time"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

// Decode public shares from pub-key.conf file...
func decodePubShares(suite *bn256.Suite, outputDir string, n int) []*share.PubShare {
	dePubShares := make([]*share.PubShare, n)
	for idx := 0; idx < n; idx++ {
		pubKeyFile := filepath.Join(outputDir, fmt.Sprintf("blsPubKey%d.json", idx))
		pubKeyBytes, err := ioutil.ReadFile(pubKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		var data keys.PubShare
		err = json.Unmarshal(pubKeyBytes, &data)
		if err != nil {
			log.Fatal(err)
		}

		point := suite.G2().Point()
		dePubShares[idx] = &share.PubShare{}
		dePubShares[idx].I = data.Index
		err = point.UnmarshalBinary(data.Pub)
		if err != nil {
			log.Fatal(err)
		}
		dePubShares[idx].V = point
	}

	return dePubShares
}

func decodePriShares(suite *bn256.Suite, outputDir string, n int) []*share.PriShare {
	dePriShares := make([]*share.PriShare, n)
	for idx := 0; idx < n; idx++ {
		priKeyFile := filepath.Join(outputDir, fmt.Sprintf("blsPriKey%d.json", idx))
		priKeyBytes, err := ioutil.ReadFile(priKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		var data keys.PriShare
		err = json.Unmarshal(priKeyBytes, &data)
		if err != nil {
			log.Fatal(err)
		}

		scalar := suite.G2().Scalar()
		err = scalar.UnmarshalBinary(data.Pri)
		if err != nil {
			log.Fatal(err)
		}
		dePriShares[idx] = &share.PriShare{}
		dePriShares[idx].I = data.Index
		dePriShares[idx].V = scalar
	}

	return dePriShares
}

func TestBLSKeyGen(t *testing.T) {
	n := 32
	q := Q(n)
	signers := n

	t.Logf("n=%d, signers=%d\n", n, signers)

	outputDir := generate(n)

	suite := bn256.NewSuite()
	pubShares := decodePubShares(suite, outputDir, n)
	priShares := decodePriShares(suite, outputDir, n)

	// Signing
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	sigsToLeader := make([][]byte, 0)
	pkToLeader := make([]*share.PubShare, 0)
	total_us := int64(0)
	for ridx := 0; ridx < signers; ridx++ {
		pk, sk := pubShares[ridx], priShares[ridx]
		start := time.Now()
		sig, err := tbls.Sign(
			suite, sk, msg,
		)
		elapsed := time.Since(start)
		total_us += elapsed.Microseconds()
		if err != nil {
			log.Fatal("tbls sign", err)
		}

		if ridx == signers-1 {
			t.Logf("siglen=%d, pklen=%d, sklen=%d\n", len(sig), len(pk.V.String()), len(sk.V.String()))
		}

		sigsToLeader = append(sigsToLeader, sig)
		pkToLeader = append(pkToLeader, pk)
	}
	t.Logf("Sign() took %f us on avg\n", float64(total_us)/float64(signers))

	// Combine()
	start := time.Now()
	pubKey, err := share.RecoverPubPoly(suite.G2(), pkToLeader, q, n)
	if err != nil {
		log.Fatal(err)
	}

	aggSig, err := tbls.Recover(suite, pubKey, msg, sigsToLeader, q, n)
	if err != nil {
		t.Error(err)
	}
	elapsed := time.Since(start)
	t.Logf("Combine() took %d us\n", elapsed.Microseconds())

	// Verification
	start = time.Now()
	err = bls.Verify(suite, pubKey.Commit(), msg, aggSig)
	if err != nil {
		t.Error(err)
	}
	elapsed = time.Since(start)
	t.Logf("Verify() took %d us\n", elapsed.Microseconds())
}
