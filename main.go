package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16Bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
)

var log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).With().Timestamp().Logger()

func main() {
	app := cli.App{
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name: "ps-vk",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vk", Required: true, Usage: "gnark VerifyingKey serialized object verification key file path"},
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
			},
			{
				Name: "json-vk",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vk", Required: true, Usage: "JSON serialized verification key file path"},
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

					err = readJsonVerifyingKey(vk.(*groth16Bn254.VerifyingKey), vkFile)

					return err
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("App failed.")
	}
}
