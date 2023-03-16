package blsgen

import (
	"blsgen/keys"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/sign/bls"
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
	n := 5
	q := Q(n)
	outputDir := generate(n)

	suite := bn256.NewSuite()
	pubShares := decodePubShares(suite, outputDir, n)
	priShares := decodePriShares(suite, outputDir, n)

	// Signing
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	sigsToLeader := make([][]byte, 0)
	pkToLeader := make([]*share.PubShare, 0)
	for ridx := 0; ridx < q; ridx++ {
		sig, err := bdn.Sign(
			suite, priShares[ridx].V, msg,
		)
		if err != nil {
			log.Fatal("tbls sign", err)
		}

		sigsToLeader = append(sigsToLeader, sig)
		pkToLeader = append(pkToLeader, pubShares[ridx])
	}

	// Verifying
	pkPoints := make([]kyber.Point, 0)
	for _, pk := range pkToLeader {
		pkPoints = append(pkPoints, pk.V)
	}
	mask, _ := sign.NewMask(suite, pkPoints, nil)
	for i := 0; i < q; i++ {
		mask.SetBit(i, true)
	}

	aggSig, err := bdn.AggregateSignatures(suite, sigsToLeader, mask)
	if err != nil {
		t.Error(err)
	}

	aggPKey, err := bdn.AggregatePublicKeys(suite, mask)
	if err != nil {
		t.Error(err)
	}

	sig, err := aggSig.MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	err = bdn.Verify(suite, aggPKey, msg, sig)
	if err != nil {
		t.Error(err)
	}

	// Test individual point
	err = bls.Verify(suite, pkPoints[1], msg, sigsToLeader[1])
	if err != nil {
		t.Error(err)
	}
}
