package main

import (
	"SAU/server"
	"flag"

	"github.com/spf13/viper"
)

var migration bool
var rollback bool

func main() {
	// set the file name of the configuration file
	viper.SetConfigType("env")
	viper.SetConfigName(".env")
	// set the configuration file path
	viper.AddConfigPath(".")
	// read in the configuration file
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}
	// mongoUrl := viper.GetString("MONGODB_URL")
	flag.BoolVar(&migration, "migration", false, "Set true to run migrations.")
	flag.BoolVar(&rollback, "rollback", false, "Set true to rollback migrations.")
	flag.Parse()

	// Pass the config to another function
	server.StartServer(viper.GetViper(), migration, rollback)

}
