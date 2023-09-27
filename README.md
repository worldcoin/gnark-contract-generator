# gnark-contract-generator

This CLI tool is able to deserialize a [gnark](https://github.com/Consensys/gnark/) verifying key from the v0.8.0 serialization format of the proving system file and generates a corresponding optimized Solidity verifier contract for the Groth16 bn254 ZK proofs. It also supports reading from [snarkjs](https://github.com/iden3/snarkjs) generated verification key JSON files like the ones provided by [PSE for the Semaphore circuits](https://www.trusted-setup-pse.org/).

## Usage

```bash
go build
# read from proving system file
./gnark-contract-generator ps-vk --vk <PS_FILENAME> --out <OUTPUT_VERIFIER_CONTRACT_FILENAME>
# read from snarkjs generated verification key JSON file
./gnark-contract-generator json-vk --vk <JSON_FILENAME> --out <OUTPUT_VERIFIER_CONTRACT_FILENAME>
```
