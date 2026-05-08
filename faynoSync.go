package main

import (
	"context"
	"faynoSync/mongod"
	"faynoSync/server"
	"flag"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	logLevel  string
)

func init() {
	flag.StringVar(&logLevel, "loglevel", "info", "log level (debug, info, warn, error, fatal, panic)")

	logrus.New()
}

func main() {
	flag.Parse()

	// Initialize logging configuration
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.Errorln("Invalid log level specified:", err)
		os.Exit(1)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Set the file name of the configuration file
	viper.SetConfigType("env")
	viper.SetConfigName(".env")
	// Set the configuration file path
	viper.AddConfigPath(".")
	// Read in the configuration file
	if err := viper.ReadInConfig(); err != nil {
		logrus.Infoln(".env file not found, using system variables")
	}

	// Enable automatic environment variable reading
	viper.AutomaticEnv()

	args := flag.Args()
	if len(args) == 0 {
		server.StartServer(viper.GetViper())
		return
	}

	if args[0] != "migrate" {
		logrus.Errorf("Unknown command %q. Supported commands: migrate up|down", args[0])
		os.Exit(1)
	}

	if len(args) != 2 || (args[1] != "up" && args[1] != "down") {
		logrus.Errorln("Usage: go run faynoSync.go [--loglevel=<level>] migrate <up|down>")
		os.Exit(1)
	}

	client, configDB := mongod.ConnectToDatabase(viper.GetString("MONGODB_URL"))
	defer client.Disconnect(context.Background())

	var migrationErr error
	if args[1] == "up" {
		migrationErr = mongod.RunMigrationsUp(client, configDB.Database)
	} else {
		migrationErr = mongod.RunMigrationsDown(client, configDB.Database)
	}
	if migrationErr != nil {
		logrus.Errorf("Migration command failed: %v", migrationErr)
		os.Exit(1)
	}
}
