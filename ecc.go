package crypto

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "runtime"
    "time"
)

func RunECCBenchmark() {
    fmt.Println("[+] ECC Benchmark")

    message := generateRandomBytes(64)
    hash := sha256.Sum256(message)

    var memStart runtime.MemStats
    runtime.ReadMemStats(&memStart)

    startKey := time.Now()
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        panic(err)
    }
    keyGenTime := time.Since(startKey)

    startSign := time.Now()
    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
    if err != nil {
        panic(err)
    }
    signTime := time.Since(startSign)

    startVerify := time.Now()
    valid := ecdsa.Verify(&privateKey.PublicKey, hash[:], r, s)
    verifyTime := time.Since(startVerify)

    var memEnd runtime.MemStats
    runtime.ReadMemStats(&memEnd)

    fmt.Printf("Tiempo de generación de claves: %v\n", keyGenTime)
    fmt.Printf("Tiempo de firma: %v\n", signTime)
    fmt.Printf("Tiempo de verificación: %v\n", verifyTime)
    fmt.Printf("Uso de memoria: %d KB\n", (memEnd.Alloc-memStart.Alloc)/1024)
    fmt.Printf("Firma válida: %v\n", valid)
}