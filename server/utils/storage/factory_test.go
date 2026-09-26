package storage

import (
	"testing"

	"github.com/spf13/viper"
)

func TestCreateStorageClientReusesClient(t *testing.T) {
	env := viper.New()
	env.Set("STORAGE_DRIVER", "minio")
	env.Set("S3_ENDPOINT", "localhost:9000")

	first, err := NewStorageFactory(env).CreateStorageClient()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	second, err := NewStorageFactory(env).CreateStorageClient()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if first != second {
		t.Fatal("expected the same client instance across factories")
	}

	other := viper.New()
	other.Set("STORAGE_DRIVER", "minio")
	other.Set("S3_ENDPOINT", "localhost:9000")
	third, err := NewStorageFactory(other).CreateStorageClient()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if third == first {
		t.Fatal("expected a separate client for a different config")
	}
}

func TestCreateStorageClientDoesNotCacheErrors(t *testing.T) {
	env := viper.New()
	env.Set("STORAGE_DRIVER", "gcp")

	if _, err := NewStorageFactory(env).CreateStorageClient(); err == nil {
		t.Fatal("expected error without GCS_CREDENTIALS_FILE")
	}

	env.Set("STORAGE_DRIVER", "minio")
	env.Set("S3_ENDPOINT", "localhost:9000")
	if _, err := NewStorageFactory(env).CreateStorageClient(); err != nil {
		t.Fatalf("create client after failed attempt: %v", err)
	}
}
