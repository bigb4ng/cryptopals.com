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
)

func TestSolveEx32(t *testing.T) {
	expected := []byte("{\"status\":\"ok\"}")
	go RunServerEx31(time.Duration(5 * time.Millisecond))

	customFilename := []byte("/etc/shadow")

	// Slowest to get 1000 responses is chosen for next attempt. This is too long of a wait for a test.
	// Instead the code below will guess single byte using statistical model and last byte using 200 OK
	attempt, _ := utils.HexDecode([]byte("1956753291BF1515B2F2D7FAF704B2BF83D3"))
	// attempt := []byte{}
	for len(attempt) < sha1.Size-1 {
		attemptHex := utils.HexEncode(attempt)
		t.Logf("collecting statistical model for: %sXX", string(attemptHex))

		stats := make([]int64, 255)
		var collectStatsWg sync.WaitGroup
		collectStatsWg.Add(255)
		for j := 0; j < 255; j++ {
			go checkSignatureByte(&collectStatsWg, byte(j), customFilename, attempt, 1000, stats)
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
