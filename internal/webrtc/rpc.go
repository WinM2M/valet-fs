package webrtc

import (
	"encoding/json"

	"github.com/google/uuid"
)

type RPCMessage struct {
	V      int            `json:"v"`
	ID     string         `json:"id,omitempty"`
	Type   string         `json:"type"`
	Method string         `json:"method,omitempty"`
	Params map[string]any `json:"params,omitempty"`
	OK     bool           `json:"ok,omitempty"`
	Result map[string]any `json:"result,omitempty"`
	Code   string         `json:"code,omitempty"`
	Msg    string         `json:"message,omitempty"`
	Topic  string         `json:"topic,omitempty"`
	Payload map[string]any `json:"payload,omitempty"`
}

func NewRequest(method string, params map[string]any) RPCMessage {
	return RPCMessage{V: 1, ID: uuid.NewString(), Type: "REQ", Method: method, Params: params}
}

func EncodeRPC(msg RPCMessage) ([]byte, error) {
	return json.Marshal(msg)
}

func DecodeRPC(b []byte) (RPCMessage, error) {
	var msg RPCMessage
	err := json.Unmarshal(b, &msg)
	return msg, err
}
