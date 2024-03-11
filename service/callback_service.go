package service

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"

	"github.com/gin-gonic/gin"
)

type CallbackServiceConfig struct {
	Address              string
	PrivateKeyPath       string
	DecryptSigKeyPath    string
	MPCNodePublicKeyPath string
	RandomReject         bool
}

type CallbackService struct {
	cfg              *CallbackServiceConfig
	PrivateKey       *ecdsa.PrivateKey
	PublicKey        *ecdsa.PublicKey
	DecryptSigKey	 *ecdsa.PrivateKey
	MPCNodePublicKey *ecdsa.PublicKey
	RandomReject     bool
}

func NewCallBackService(cfg *CallbackServiceConfig) (*CallbackService, error) {
	tssNodePublicKey, err := loadTSSNodePublicKey(cfg.MPCNodePublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load mpc-node public key failed, %v", err)
	}
	private, public, err := loadKeypair(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load callback server keypair failed, %v", err)
	}

	privateSigKey, _, err := loadKeypair(cfg.DecryptSigKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load decrypte sig keypair failed, %v", err)
	}
	return &CallbackService{
		cfg:              cfg,
		PrivateKey:       private,
		PublicKey:        public,
		DecryptSigKey:	  privateSigKey,
		MPCNodePublicKey: tssNodePublicKey,
		RandomReject:     cfg.RandomReject,
	}, nil
}

func (c *CallbackService) Start() error {
	r := gin.Default()
	api := r.Group("/v1")
	api.POST("/check", c.Check)
	api.POST("/rawdata_signature", c.RawDataSignature)

	log.Fatal(r.Run(c.cfg.Address))

	return nil
}

func (c *CallbackService) Stop() error {
	return nil
}

func (c *CallbackService) Check(g *gin.Context) {
	var err error
	//var selected string
	request := &Check{}
	if err := g.BindJSON(request); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "parse check request failed"})
		return
	}
	signature, ok := g.Request.Header["Signature"]
	if !ok {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "signature not found"})
		return
	}
	log.Printf("check request with signature: %v", signature)
	if message, err := json.Marshal(request); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "marshal check request failed"})
		return
	} else if !Verify(c.MPCNodePublicKey, hex.EncodeToString(message), signature[0]) {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "verify signature failed"})
		return
	}
	log.Printf("new check request, callback-id: [%s] request-type: [%s] sino-id: [%s] request-id: [%s] sign-type: [%s] t: [%d] n: [%d] cryptography: [%s] party-ids: [%v] message: [%s] signature: [%s] tx_info: [%s] ",
		request.CallbackId,
		request.RequestType,
		request.ExtraInfo.SinoId, request.ExtraInfo.RequestId,
		request.SignType,
		request.RequestDetail.T, request.RequestDetail.N, request.RequestDetail.Cryptography, request.RequestDetail.PartyIds,
		request.RequestDetail.Message, request.RequestDetail.Signature,
		string(request.TxInfo))
	response := &Response{
		Status:    "0",
		Signature: "",
		Data: &ResponseData{
			CallbackId: request.CallbackId,
			SinoId:     request.ExtraInfo.SinoId,
			RequestId:  request.ExtraInfo.RequestId,
			Action:     c.randAction(request.RequestType),
		},
	}
	if response.Data.Action == Wait {
		response.Data.WaitTime = "60"
	}
	message, err := json.Marshal(response.Data)
	if err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "marshal check response failed"})
		return
	}
	if signature, err := Sign(c.PrivateKey, hex.EncodeToString(message)); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "sign check response failed"})
		return
	} else {
		response.Signature = signature
	}
	g.JSON(http.StatusOK, response)
}

func (c *CallbackService) RawDataSignature(g *gin.Context) {
	//var selected string
	request := &Check{}
	if err := g.BindJSON(request); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "parse check request failed"})
		return
	}
	signature, ok := g.Request.Header["Signature"]
	if !ok {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "signature not found"})
		return
	}
	log.Printf("check request with signature: %v", signature)
	if message, err := json.Marshal(request); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "marshal check request failed"})
		return
	} else if !Verify(c.MPCNodePublicKey, hex.EncodeToString(message), signature[0]) {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "verify signature failed"})
		return
	}

	decodeSig, err := Decrypt(c.DecryptSigKey, request.RequestDetail.Signature)
	if err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "501", "error": "decrypt sig error"})
		return
	}
	log.Printf("receive raw data signature, callback-id: [%s] message: [%s] signature: [%s] sino-id: [%s] request-id: [%s]",
		request.CallbackId,
		request.RequestDetail.Message,
		decodeSig,
		request.ExtraInfo.SinoId, request.ExtraInfo.RequestId)
	// g.JSON(http.StatusOK, gin.H{"status": "0"})

	response := &Response{
		Status:    "0",
		Signature: "",
		Data: &ResponseData{
			CallbackId: request.CallbackId,
			SinoId:     request.ExtraInfo.SinoId,
			RequestId:  request.ExtraInfo.RequestId,
			Action:     c.randAction(request.RequestType),
		},
	}
	if response.Data.Action == Wait {
		response.Data.WaitTime = "60"
	}
	message, err := json.Marshal(response.Data)
	if err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "marshal check response failed"})
		return
	}
	if signature, err := Sign(c.PrivateKey, hex.EncodeToString(message)); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"status": "400", "error": "sign check response failed"})
		return
	} else {
		response.Signature = signature
	}
	g.JSON(http.StatusOK, response)
}

const (
	Approve = "APPROVE"
	Reject  = "REJECT"
	Wait    = "WAIT"
)

func (c *CallbackService) randAction(t string) string {
	if c.RandomReject == false {
		return Approve
	}
	switch t {
	case "keygen":
		return Approve
	default:
		r := rand.Float32()
		if r < 0.80 {
			return Approve
		} else if r < 0.90 {
			return Reject
		} else {
			return Wait
		}
	}
}
