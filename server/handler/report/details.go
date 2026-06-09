package report

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"faynoSync/server/model"
	"io"
	"net/http"
)

const (
	detailsEncoding                     = "gzip+base64"
	detailsContentType                  = "application/json"
	defaultMaxDetailsCompressed   int64 = 131072
	defaultMaxDetailsDecompressed int64 = 1048576
)

type decodedDetails struct {
	compressed       []byte
	decompressedSize int64
}

func decodeAndValidateDetails(d *model.ReportDetails, maxCompressed, maxDecompressed int64) (*decodedDetails, int, string) {
	if d.Encoding != detailsEncoding {
		return nil, http.StatusBadRequest, "unsupported details encoding"
	}
	if d.ContentType != detailsContentType {
		return nil, http.StatusBadRequest, "unsupported details content_type"
	}

	// Reject an oversized base64 string before allocating the decoded buffer.
	if int64(len(d.Payload)) > int64(base64.StdEncoding.EncodedLen(int(maxCompressed))) {
		return nil, http.StatusRequestEntityTooLarge, "compressed details too large"
	}

	compressed, err := base64.StdEncoding.DecodeString(d.Payload)
	if err != nil {
		return nil, http.StatusBadRequest, "invalid details payload encoding"
	}
	if int64(len(compressed)) > maxCompressed {
		return nil, http.StatusRequestEntityTooLarge, "compressed details too large"
	}

	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, http.StatusBadRequest, "invalid details payload"
	}
	defer gz.Close()

	decompressed, err := io.ReadAll(io.LimitReader(gz, maxDecompressed+1))
	if err != nil {
		return nil, http.StatusBadRequest, "invalid details payload"
	}
	if int64(len(decompressed)) > maxDecompressed {
		return nil, http.StatusRequestEntityTooLarge, "decompressed details too large"
	}

	return &decodedDetails{compressed: compressed, decompressedSize: int64(len(decompressed))}, 0, ""
}
