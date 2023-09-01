package service

import "encoding/json"

type Check struct {
	CallbackId    string `json:"callback_id,omitempty"` // 由mpc-node生成，每次请求callback server时生成一个新的
	RequestType   string `json:"request_type,omitempty"`
	RequestDetail `json:"request_detail,omitempty"`
	ExtraInfo     `json:"extra_info,omitempty"`
}

type RequestDetail struct {
	T            int      `json:"t,omitempty"`
	N            int      `json:"n,omitempty"`
	Cryptography string   `json:"cryptography,omitempty"`
	PartyIds     []string `json:"party_ids,omitempty"`

	SignType  string          `json:"sign_type,omitempty" form:"sign_type"`
	PublicKey string          `json:"public_key,omitempty"`
	Path      string          `json:"path,omitempty"`
	Message   string          `json:"message,omitempty"`
	Signature string          `json:"signature,omitempty"`
	TxInfo    json.RawMessage `json:"tx_info,omitempty" form:"tx_info"`
}

type ExtraInfo struct {
	SinoId    string `json:"sino_id,omitempty"`
	RequestId string `json:"request_id,omitempty"`
}

type Response struct {
	Status    string        `json:"status,omitempty"`
	Error     string        `json:"error,omitempty"`
	Data      *ResponseData `json:"data,omitempty"`
	Signature string        `json:"signature,omitempty"`
}

type ResponseData struct {
	CallbackId string `json:"callback_id,omitempty"`
	SinoId     string `json:"sino_id,omitempty"`
	RequestId  string `json:"request_id,omitempty"`
	Action     string `json:"action,omitempty"`
	WaitTime   string `json:"wait_time,omitempty"`
}
