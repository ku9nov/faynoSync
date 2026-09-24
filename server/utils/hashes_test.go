package utils

import (
	"bytes"
	"io"
	"mime/multipart"
	"testing"
)

func uploadedFile(t *testing.T, name string, content []byte) *multipart.FileHeader {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	form, err := multipart.NewReader(&body, writer.Boundary()).ReadForm(int64(len(content)) + 4096)
	if err != nil {
		t.Fatalf("ReadForm: %v", err)
	}
	return form.File["file"][0]
}

// The hashes end up in TUF targets metadata, so they must be of the artifact bytes
// exactly, with no framing from the multipart envelope.
func TestCalculateFileHashes(t *testing.T) {
	cases := []struct {
		name       string
		content    []byte
		wantSHA256 string
		wantSHA512 string
	}{
		{
			name:       "artifact bytes",
			content:    []byte("faynoSync artifact bytes"),
			wantSHA256: "3eaed3676200e67ae9d444338ee6b20f0781967569da5016867dffe7ab480395",
			wantSHA512: "6312201f1677115adbd5e57768005d0f43f5f8d39a10ac8425d081a3646f1735ac510cd3695184490690de6d572d22f36e4048d727ddf150adad6da8bb7ee27c",
		},
		{
			name:       "empty file",
			content:    []byte{},
			wantSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantSHA512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hashes, length, err := CalculateFileHashes(uploadedFile(t, "MyApp-1.0.0.dmg", tc.content))
			if err != nil {
				t.Fatalf("CalculateFileHashes: %v", err)
			}
			if hashes["sha256"] != tc.wantSHA256 {
				t.Errorf("sha256 = %q, want %q", hashes["sha256"], tc.wantSHA256)
			}
			if hashes["sha512"] != tc.wantSHA512 {
				t.Errorf("sha512 = %q, want %q", hashes["sha512"], tc.wantSHA512)
			}
			if length != int64(len(tc.content)) {
				t.Errorf("length = %d, want %d", length, len(tc.content))
			}
		})
	}
}

// Upload hashes the file and only then streams it to storage, so hashing must not
// consume the upload's reader.
func TestCalculateFileHashesLeavesFileReadable(t *testing.T) {
	content := []byte("faynoSync artifact bytes")
	file := uploadedFile(t, "MyApp-1.0.0.dmg", content)

	first, firstLength, err := CalculateFileHashes(file)
	if err != nil {
		t.Fatalf("first CalculateFileHashes: %v", err)
	}

	second, secondLength, err := CalculateFileHashes(file)
	if err != nil {
		t.Fatalf("second CalculateFileHashes: %v", err)
	}
	if first["sha256"] != second["sha256"] || first["sha512"] != second["sha512"] || firstLength != secondLength {
		t.Errorf("second call = %v/%d, want %v/%d", second, secondLength, first, firstLength)
	}

	reader, err := file.Open()
	if err != nil {
		t.Fatalf("Open after hashing: %v", err)
	}
	defer reader.Close()

	read, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll after hashing: %v", err)
	}
	if !bytes.Equal(read, content) {
		t.Errorf("file content after hashing = %q, want %q", read, content)
	}
}
