package kyber_generator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"
	"time"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

// Decode public shares from pub-key.conf file...
func decodePubPoly(suite *bn256.Suite, outputDir string, n, t int) *share.PubPoly {
	pubKeyFile := filepath.Join(outputDir, "bls-public-key.json")
	// Read public keys from file.
	plan, _ := ioutil.ReadFile(pubKeyFile)
	var data []PubShare
	err := json.Unmarshal(plan, &data)
	if err != nil {
		log.Fatal("Couldn't Unmarshal public key json", "err", err)
	}

	dePubShares := make([]*share.PubShare, n)

	for i, d := range data {
		point := suite.G2().Point()
		var err error
		dePubShares[i] = &share.PubShare{}
		dePubShares[i].I = d.Index
		err = point.UnmarshalBinary(d.Pub)
		if err != nil {
			log.Fatal("Couldn't Unmarshal public key binary", "idx", i, "err", err)
		}
		dePubShares[i].V = point
	}
	// Recover public key.
	pubKey, err := share.RecoverPubPoly(suite.G2(), dePubShares, t, n)
	if err != nil {
		log.Fatal("Couldn't recover BLS public key", "err", err)
	}
	return pubKey
}

func decodePriShares(suite *bn256.Suite, outputDir string, n int) []*share.PriShare {
	dePriShares := make([]*share.PriShare, n)
	for idx := 0; idx < n; idx++ {
		priKeyFile := filepath.Join(outputDir, fmt.Sprintf("bls-private-key%d.json", idx))
		priKeyBytes, err := ioutil.ReadFile(priKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		var data PriShare
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

	outputDir := Generate(n)

	fmt.Printf("outputDir at %s\n", outputDir)

	suite := bn256.NewSuite()
	pubKey := decodePubPoly(suite, outputDir, n, Q(n))
	priShares := decodePriShares(suite, outputDir, n)

	// Signing
	msg := []byte("random message")
	sigsToLeader := make([][]byte, 0)
	total_us := int64(0)
	for ridx := 0; ridx < signers; ridx++ {
		sk := priShares[ridx]
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
			t.Logf("siglen=%d, sklen=%d\n", len(sig), len(sk.V.String()))
		}

		sigsToLeader = append(sigsToLeader, sig)
	}
	t.Logf("Sign() took %f us on avg\n", float64(total_us)/float64(signers))

	// Combine()
	start := time.Now()
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
