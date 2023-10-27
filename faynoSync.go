package main

import (
	"faynoSync/server"
	"flag"

	"github.com/spf13/viper"
)

var migration bool
var rollback bool
var userName string
var userPassword string

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
	flag.BoolVar(&migration, "migration", false, "Set true to run migrations.")
	flag.BoolVar(&rollback, "rollback", false, "Set true to rollback migrations.")
	// flag.StringVar(&userName, "username", "", "Set admin username.")
	// flag.StringVar(&userPassword, "password", "", "Set admin password.")
	flag.Parse()

	flagMap := map[string]interface{}{
		"migration": migration,
		"rollback":  rollback,
		// "user_name":     userName,
		// "user_password": userPassword,
	}

	// Pass the config to another function
	server.StartServer(viper.GetViper(), flagMap)

}
