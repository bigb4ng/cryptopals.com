package set4

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"main/pkg/utils"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func RunServerEx31(compareDelay time.Duration) {
	secret := []byte("very secret")

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/", func(ctx *gin.Context) {
		filename := ctx.Query("file")
		if filename == "" {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		signatureHex := ctx.Query("signature")
		if signatureHex == "" {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		providedSignature, err := utils.HexDecode([]byte(signatureHex))
		if err != nil || len(providedSignature) != sha1.Size {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		msg := []byte(secret)
		msg = append(msg, filename...)
		expectedSignature := sha1.Sum(msg)

		for i := range providedSignature {
			if providedSignature[i] != expectedSignature[i] {
				ctx.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			time.Sleep(compareDelay)
		}

		ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.Run()
}

func checkSignatureByte(wg *sync.WaitGroup, b byte, filename, attempt []byte, attemptsNum int, stats []int64) {
	defer wg.Done()

	signature := make([]byte, sha1.Size)
	signature[copy(signature, attempt)] = b
	signatureHex := utils.HexEncode(signature)

	client := http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:8080/?file=%s&signature=%s", filename, signatureHex), nil)

	start := time.Now().UnixMilli()
	for i := 0; i < attemptsNum; i++ {
		_, _ = client.Do(req)
	}
	end := time.Now().UnixMilli()

	stats[b] = end - start
}

func findLastByte(filename []byte, attempt []byte) byte {
	resultChan := make(chan byte, 1)
	for i := 0; i < 255; i++ {
		signature := make([]byte, sha1.Size)
		signature[copy(signature, attempt)] = byte(i)
		signatureHex := utils.HexEncode(signature)

		go func(matchHex []byte, b byte) {
			resp, _ := http.Get(fmt.Sprintf("http://localhost:8080/?file=%s&signature=%s", filename, matchHex))
			if resp.StatusCode == http.StatusOK {
				resultChan <- b
			}
		}(signatureHex, byte(i))
	}

	return <-resultChan
}

func TestSolveEx31(t *testing.T) {
	expected := []byte("{\"status\":\"ok\"}")
	go RunServerEx31(time.Duration(50 * time.Millisecond))

	customFilename := []byte("/etc/shadow")

	// Slowest to get 10 responses is chosen for next attempt
	attempt := []byte{}
	for len(attempt) < sha1.Size-1 {
		attemptHex := utils.HexEncode(attempt)
		t.Logf("collecting statistical model for: %sXX", string(attemptHex))

		stats := make([]int64, 255)
		var collectStatsWg sync.WaitGroup
		collectStatsWg.Add(255)
		for j := 0; j < 255; j++ {
			go checkSignatureByte(&collectStatsWg, byte(j), customFilename, attempt, 10, stats)
		}
		collectStatsWg.Wait()

		// Find slowest
		var maxTtl int64
		var maxByte byte
		for i, time := range stats {
			if time > maxTtl {
				maxTtl = time
				maxByte = byte(i)
			}
		}

		attempt = append(attempt, maxByte)
	}

	// Last byte will return 200 OK on match, so look for that
	result := append(attempt, findLastByte(customFilename, attempt))
	resultHex := utils.HexEncode(result)

	t.Logf("result: %s", resultHex)
	resp, err := http.Get(fmt.Sprintf("http://localhost:8080/?file=%s&signature=%s", customFilename, resultHex))
	if err != nil {
		t.Fatalf("error getting file: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body: %v", err)
	}

	if !bytes.Equal(body, expected) {
		t.Fatalf("unexpected response body: %s != %s", body, expected)
	}
}
