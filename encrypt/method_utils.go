package encrypt

import (
	"errors"
	"reflect"
)

const (
	encryptMethodRaw = iota
	encryptMethodAES128CFB
	encryptMethodAES192CFB
	encryptMethodAES256CFB
)

var (
	encryptKey = ""
	encryptIv  = ""
)

var methods = map[string]reflect.Type{
	"raw":         reflect.TypeOf(new(RawMethod)).Elem(),
	"aes-128-cfb": reflect.TypeOf(new(AES128CFBMethod)).Elem(),
	"aes-192-cfb": reflect.TypeOf(new(AES192CFBMethod)).Elem(),
	"aes-256-cfb": reflect.TypeOf(new(AES256CFBMethod)).Elem(),
}

func Init(key string, iv string) {
	encryptKey, encryptIv = key, iv
}
func NewMethodInstance(method string, key string, iv string) (MethodInterface, error) {
	valueType, ok := methods[method]
	if !ok {
		return nil, errors.New("method '" + method + "' not found")
	}
	instance, ok := reflect.New(valueType).Interface().(MethodInterface)
	if !ok {
		return nil, errors.New("method '" + method + "' must implement MethodInterface")
	}
	err := instance.Init([]byte(key), []byte(iv))
	return instance, err
}
func GetMethodInstance(id uint8) (MethodInterface, error) {
	method := ""
	switch id {
	case encryptMethodRaw:
		method = "raw"
	case encryptMethodAES128CFB:
		method = "aes-128-cfb"
	case encryptMethodAES192CFB:
		method = "aes-192-cfb"
	case encryptMethodAES256CFB:
		method = "aes-256-cfb"
	}
	return NewMethodInstance(method, encryptKey, encryptIv)
}
func RecoverMethodPanic(err interface{}) error {
	if err != nil {
		s, ok := err.(string)
		if ok {
			return errors.New(s)
		}

		e, ok := err.(error)
		if ok {
			return e
		}

		return errors.New("unknown error")
	}
	return nil
}
