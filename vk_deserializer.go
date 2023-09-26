package main

import (
	"encoding/json"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	groth16Bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func readV08VerifyingKey(vk *groth16Bn254.VerifyingKey, r io.Reader) (int64, error) {
	dec := bn254.NewDecoder(r)
	if err := dec.Decode(&vk.G1.Alpha); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G1.Beta); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G2.Beta); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G2.Gamma); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G1.Delta); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G2.Delta); err != nil {
		return dec.BytesRead(), err
	}

	// uint32(len(Kvk)),[Kvk]1
	if err := dec.Decode(&vk.G1.K); err != nil {
		return dec.BytesRead(), err
	}

	if err := vk.Precompute(); err != nil {
		return dec.BytesRead(), err
	}

	return dec.BytesRead(), nil
}

// G1 projective point coordinates
type g1ProjJson struct {
	coords [3]string
}

// G2 projective point coordinates
type g2ProjJson struct {
	coords [3][2]string
}

type vkJson struct {
	AlphaG1 g1ProjJson `json:"vk_alpha_1"`
	BetaG2  g2ProjJson `json:"vk_beta_2"`
	GammaG2 g2ProjJson `json:"vk_gamma_2"`
	DeltaG2 g2ProjJson `json:"vk_delta_2"`
	// length dependent on circuit public inputs
	G1K []g1ProjJson `json:"IC"`
}

func readJsonVerifyingKey(vk *groth16Bn254.VerifyingKey, r io.Reader) error {
	data, err := io.ReadAll(r)

	if err != nil {
		return err
	}

	var vkJson vkJson

	err = json.Unmarshal(data, &vkJson)

	if err != nil {
		return err
	}

	vk.G1.Alpha.X.SetString(vkJson.AlphaG1.coords[0])
	vk.G1.Alpha.Y.SetString(vkJson.AlphaG1.coords[1])
	vk.G2.Beta.X.SetString(vkJson.BetaG2.coords[0][0], vkJson.BetaG2.coords[0][1])
	vk.G2.Beta.Y.SetString(vkJson.BetaG2.coords[1][0], vkJson.BetaG2.coords[1][1])
	vk.G2.Gamma.X.SetString(vkJson.GammaG2.coords[0][0], vkJson.GammaG2.coords[0][1])
	vk.G2.Gamma.Y.SetString(vkJson.GammaG2.coords[1][0], vkJson.GammaG2.coords[1][1])
	vk.G2.Delta.X.SetString(vkJson.DeltaG2.coords[0][0], vkJson.DeltaG2.coords[0][1])
	vk.G2.Delta.Y.SetString(vkJson.DeltaG2.coords[1][0], vkJson.DeltaG2.coords[1][1])
	vk.G1.K = make([]bn254.G1Affine, len(vkJson.G1K))

	for i := 0; i < len(vkJson.G1K); i++ {
		vk.G1.K[i].X.SetString(vkJson.G1K[i].coords[0])
		vk.G1.K[i].Y.SetString(vkJson.G1K[i].coords[1])
	}

	vk.Precompute()

	return nil
}
