package main

import (
	"faynoSync/server"
	"flag"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	migration bool
	rollback  bool
	logLevel  string
)

func init() {
	flag.BoolVar(&migration, "migration", false, "Set true to run migrations.")
	flag.BoolVar(&rollback, "rollback", false, "Set true to rollback migrations.")
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

	flagMap := map[string]interface{}{
		"migration": migration,
		"rollback":  rollback,
	}

	// Pass the config to another function
	server.StartServer(viper.GetViper(), flagMap)
}
