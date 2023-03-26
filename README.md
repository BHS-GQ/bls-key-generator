# BLS Key Generator
Using `kyber/v3`


# Instructions
Takes in the total number of validators `n` as an arg. Sets threshold to quorum size.

Run using the ff:

```
go run . n
```

For example:

```
go run . 4
```

Will generate a file in `temp/...` with the ff contents:

```
<n>_<timestamp>
├── bls-private-key0.json
├── bls-private-key1.json
├── bls-private-key2.json
├── bls-private-key3.json
└── bls-public-key.json
```
