package crypto

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "runtime"
    "time"
)

func RunRSABenchmark() {
    fmt.Println("[+] RSA Benchmark")

    message := generateRandomBytes(190)

    var memStart runtime.MemStats
    runtime.ReadMemStats(&memStart)

    startKey := time.Now()
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        panic(err)
    }
    keyGenTime := time.Since(startKey)
    publicKey := &privateKey.PublicKey

    startEnc := time.Now()
    ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
    if err != nil {
        panic(err)
    }
    durationEnc := time.Since(startEnc)

    startDec := time.Now()
    plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
    if err != nil {
        panic(err)
    }
    durationDec := time.Since(startDec)

    var memEnd runtime.MemStats
    runtime.ReadMemStats(&memEnd)

    fmt.Printf("Tiempo de generación de claves: %v\n", keyGenTime)
    fmt.Printf("Tiempo de cifrado: %v\n", durationEnc)
    fmt.Printf("Tiempo de descifrado: %v\n", durationDec)
    fmt.Printf("Tamaño del texto cifrado: %d bytes\n", len(ciphertext))
    fmt.Printf("Uso de memoria: %d KB\n", (memEnd.Alloc-memStart.Alloc)/1024)
    fmt.Printf("Correcto: %v\n", string(message) == string(plaintext))
    fmt.Println("Texto cifrado (hex):", hex.EncodeToString(ciphertext[:32]), "...")
}