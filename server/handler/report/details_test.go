package report

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"faynoSync/server/model"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gzipB64(t *testing.T, data []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func details(encoding, contentType, payload string) *model.ReportDetails {
	return &model.ReportDetails{Encoding: encoding, ContentType: contentType, Payload: payload}
}

func TestDecodeDetailsValid(t *testing.T) {
	body := []byte(`{"message":"expected sha256 != actual sha256"}`)
	d := details("gzip+base64", "application/json", gzipB64(t, body))

	res, status, msg := decodeAndValidateDetails(d, defaultMaxDetailsCompressed, defaultMaxDetailsDecompressed)
	require.Equal(t, 0, status, "msg: %s", msg)
	require.NotNil(t, res)
	assert.Equal(t, int64(len(body)), res.decompressedSize)
	assert.NotEmpty(t, res.compressed)
}

func TestDecodeDetailsUnsupportedEncoding(t *testing.T) {
	d := details("zstd", "application/json", gzipB64(t, []byte(`{}`)))
	_, status, _ := decodeAndValidateDetails(d, defaultMaxDetailsCompressed, defaultMaxDetailsDecompressed)
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestDecodeDetailsUnsupportedContentType(t *testing.T) {
	d := details("gzip+base64", "text/plain", gzipB64(t, []byte(`{}`)))
	_, status, _ := decodeAndValidateDetails(d, defaultMaxDetailsCompressed, defaultMaxDetailsDecompressed)
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestDecodeDetailsInvalidBase64(t *testing.T) {
	d := details("gzip+base64", "application/json", "not!!base64")
	_, status, _ := decodeAndValidateDetails(d, defaultMaxDetailsCompressed, defaultMaxDetailsDecompressed)
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestDecodeDetailsInvalidGzip(t *testing.T) {
	// Valid base64 but not gzip data.
	d := details("gzip+base64", "application/json", base64.StdEncoding.EncodeToString([]byte("plain not gzip")))
	_, status, _ := decodeAndValidateDetails(d, defaultMaxDetailsCompressed, defaultMaxDetailsDecompressed)
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestDecodeDetailsCompressedTooLarge(t *testing.T) {
	// Random-ish data won't compress; compressed size exceeds a tiny limit.
	body := bytes.Repeat([]byte("abcdefgh"), 256) // 2KB
	d := details("gzip+base64", "application/json", gzipB64(t, body))
	_, status, _ := decodeAndValidateDetails(d, 16, defaultMaxDetailsDecompressed)
	assert.Equal(t, http.StatusRequestEntityTooLarge, status)
}

func TestDecodeDetailsDecompressedTooLarge(t *testing.T) {
	// Highly compressible: small compressed, large decompressed (zip-bomb shape).
	body := bytes.Repeat([]byte("a"), 200000)
	d := details("gzip+base64", "application/json", gzipB64(t, body))

	// Generous compressed budget, tiny decompressed limit -> LimitReader trips.
	res, status, _ := decodeAndValidateDetails(d, defaultMaxDetailsCompressed, 1000)
	assert.Equal(t, http.StatusRequestEntityTooLarge, status)
	assert.Nil(t, res)
}

func TestDecodeDetailsDecompressedAtLimit(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 1000)
	d := details("gzip+base64", "application/json", gzipB64(t, body))

	res, status, msg := decodeAndValidateDetails(d, defaultMaxDetailsCompressed, 1000)
	require.Equal(t, 0, status, "msg: %s", msg)
	assert.Equal(t, int64(1000), res.decompressedSize)
}
