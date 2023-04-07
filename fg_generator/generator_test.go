package fg_generator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"path/filepath"
	"testing"

	fg_crypto "github.com/onflow/flow-go/crypto"
)

var (
	salg fg_crypto.SigningAlgorithm = fg_crypto.BLSBLS12381
)

func decodePubKeys(outputDir string, n int) ([]fg_crypto.PublicKey, fg_crypto.PublicKey) {
	var pkGroup fg_crypto.PublicKey
	pkShares := make([]fg_crypto.PublicKey, n)
	for idx := 0; idx < n; idx++ {
		pubKeyFile := filepath.Join(outputDir, fmt.Sprintf("bls-public-key%d.json", idx))
		pubKeyBytes, err := ioutil.ReadFile(pubKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		var data PubKey
		err = json.Unmarshal(pubKeyBytes, &data)
		if err != nil {
			log.Fatal(err)
		}

		if idx == 0 {
			pkGroup, err = fg_crypto.DecodePublicKey(salg, data.Group)
			if err != nil {
				log.Fatal("DecodePublicKey() Group ", err, data.Group)
			}
		}
		pkShare, err := fg_crypto.DecodePublicKey(salg, data.Share)
		if err != nil {
			log.Fatal("DecodePublicKey()", err, data.Share)
		}
		pkShares[idx] = pkShare
	}

	return pkShares, pkGroup
}

func decodePriKeys(outputDir string, n int) []fg_crypto.PrivateKey {
	skShares := make([]fg_crypto.PrivateKey, n)
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

		skShare, err := fg_crypto.DecodePrivateKey(salg, data.Pri)
		if err != nil {
			log.Println("DecodePrivateKey()", err)
		}
		skShares[idx] = skShare
	}

	return skShares
}

func TestBLSKeyGen(t *testing.T) {
	n := 5
	q := Q(n)
	n_signers := n

	t.Logf("n=%d, q=%d, signers=%d\n", n, q, n_signers)

	outputDir := Generate(n)

	fmt.Printf("outputDir at %s\n", outputDir)

	kmac := fg_crypto.NewExpandMsgXOFKMAC128(thresholdSignatureTag)
	pkShares, pkGroup := decodePubKeys(outputDir, n)
	skShares := decodePriKeys(outputDir, n)

	signers := make([]int, 0, n)
	// fill the signers list and shuffle it
	for i := 0; i < n; i++ {
		signers = append(signers, i)
	}
	mrand.Shuffle(n, func(i, j int) {
		signers[i], signers[j] = signers[j], signers[i]
	})

	msg := []byte("random message")
	signerIds := make([]int, 0, n_signers)
	signShares := make([]fg_crypto.Signature, 0, n)
	for i := 0; i < n_signers; i++ {
		sidx := signers[i]
		sk := skShares[sidx]
		share, err := sk.Sign(msg, kmac)
		if err != nil {
			t.Fatal(err)
		}

		signShares = append(signShares, share)
		signerIds = append(signerIds, sidx)
	}

	for i := 0; i < n_signers; i++ {
		sidx := signers[i]
		share := signShares[i]
		verif, err := pkShares[sidx].Verify(share, msg, kmac)
		if err != nil {
			t.Fatal(err)
		}
		if verif != true {
			t.Fatalf("pkShare verification failed on sidx=%d", sidx)
		}
	}

	// reconstruct and test the threshold signature
	thresholdSignature, err := fg_crypto.BLSReconstructThresholdSignature(n, q, signShares, signerIds)
	if err != nil {
		t.Fatal(err)
	}

	verif, err := pkGroup.Verify(thresholdSignature, msg, kmac)
	if err != nil {
		t.Fatal(err)
	}
	if verif != true {
		t.Fatalf("Threshold signature verification failed")
	}
}
