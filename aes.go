package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "io"
    "runtime"
    "time"
)

func generateRandomBytes(size int) []byte {
    b := make([]byte, size)
    if _, err := io.ReadFull(rand.Reader, b); err != nil {
        panic(err)
    }
    return b
}

func encryptAES(plaintext, key, iv []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    padding := aes.BlockSize - len(plaintext)%aes.BlockSize
    for i := 0; i < padding; i++ {
        plaintext = append(plaintext, byte(padding))
    }

    ciphertext := make([]byte, len(plaintext))
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext, plaintext)
    return ciphertext
}

func decryptAES(ciphertext, key, iv []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(ciphertext))
    mode.CryptBlocks(plaintext, ciphertext)

    padding := int(plaintext[len(plaintext)-1])
    return plaintext[:len(plaintext)-padding]
}

func RunAESBenchmark() {
    fmt.Println("[+] AES Benchmark")

    plaintext := generateRandomBytes(1024 * 1024)
    key := generateRandomBytes(32)
    iv := generateRandomBytes(aes.BlockSize)

    var memStart runtime.MemStats
    runtime.ReadMemStats(&memStart)

    startEnc := time.Now()
    ciphertext := encryptAES(plaintext, key, iv)
    durationEnc := time.Since(startEnc)

    startDec := time.Now()
    decrypted := decryptAES(ciphertext, key, iv)
    durationDec := time.Since(startDec)

    var memEnd runtime.MemStats
    runtime.ReadMemStats(&memEnd)

    fmt.Printf("Tiempo de cifrado: %v\n", durationEnc)
    fmt.Printf("Tiempo de descifrado: %v\n", durationDec)
    fmt.Printf("Tamaño del texto cifrado: %d bytes\n", len(ciphertext))
    fmt.Printf("Uso de memoria: %d KB\n", (memEnd.Alloc-memStart.Alloc)/1024)
    fmt.Printf("Correcto: %v\n", string(plaintext) == string(decrypted))
    fmt.Println("Texto cifrado (hex):", hex.EncodeToString(ciphertext[:32]), "...")
}