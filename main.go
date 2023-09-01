package main

import (
	"flag"
	"log"

	"github.com/sinohope/mpc-node-callback-demo/service"
)

var (
	version              = flag.Bool("version", false, "show version")
	address              = flag.String("address", "0.0.0.0:9090", "callback-server address")
	path                 = flag.String("path", "./callback_server_private.pem", "callback-server private key path")
	mpcNodePublicKeyPath = flag.String("mpc-node-public-key-path", "./mpc_node_public.pem", "mpc-node public key path")
	random               = flag.Bool("random", false, "Random reject sign request")
)

func main() {
	flag.Parse()

	if *version {
		return
	}

	cfg := &service.CallbackServiceConfig{
		Address:              *address,
		PrivateKeyPath:       *path,
		MPCNodePublicKeyPath: *mpcNodePublicKeyPath,
		RandomReject:         *random,
	}
	if s, err := service.NewCallBackService(cfg); err != nil {
		log.Fatal(err)
	} else if err = s.Start(); err != nil {
		log.Fatal(err)
	}
}
