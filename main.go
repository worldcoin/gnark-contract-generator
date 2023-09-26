package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16Bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
	"io"
	"os"
)

var log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).With().Timestamp().Logger()

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

func main() {
	app := cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "vk", Required: true, Usage: "verification key file path"},
			&cli.StringFlag{Name: "out", Required: true, Usage: "solidity output file path"},
		},
		Action: func(context *cli.Context) error {
			vkPath := context.String("vk")
			vkFile, err := os.Open(vkPath)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to open verification key file.")
				return err
			}
			defer vkFile.Close()
			vk := groth16.NewVerifyingKey(ecc.BN254)
			_, err = readV08VerifyingKey(vk.(*groth16Bn254.VerifyingKey), vkFile)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to read verification key.")
				return err
			}
			outPath := context.String("out")
			outFile, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer outFile.Close()
			return vk.ExportSolidity(outFile)
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("App failed.")
	}
}
