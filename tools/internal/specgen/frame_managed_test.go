package specgen

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestFrameManagedAPIs(t *testing.T) {
	generator := New()
	files, err := filepath.Glob("../../../src/schemas/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := generator.AddSchemas(data); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"sign", "submit"} {
		data, err := os.ReadFile("../../../src/eth/" + file + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		if err := generator.AddMethods(data); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"eth_signTransaction", "eth_sendTransaction"} {
		method := generator.methods[name]
		schemas := []object{method["params"].([]any)[0].(object)["schema"].(object), method["result"].(object)["schema"].(object)}
		for _, example := range method["examples"].([]any) {
			example := example.(object)
			if !strings.HasPrefix(example["name"].(string), "Frame transaction ") {
				continue
			}
			values := []any{example["params"].([]any)[0].(object)["value"], example["result"].(object)["value"]}
			for _, expanded := range []bool{false, true} {
				for i, schema := range schemas {
					t.Run(name+"/"+example["name"].(string), func(t *testing.T) {
						root := object{"components": object{"schemas": repo2object(generator.types)}, "$ref": schema["$ref"]}
						if expanded {
							root, err = generator.expandSchema(schema, generator.types)
							if err != nil {
								t.Fatal(err)
							}
						}
						compiler := jsonschema.NewCompiler()
						compiler.DefaultDraft(jsonschema.Draft7)
						if err := compiler.AddResource("managed.json", root); err != nil {
							t.Fatal(err)
						}
						compiled, err := compiler.Compile("managed.json")
						if err != nil {
							t.Fatal(err)
						}
						data, err := json.Marshal(values[i])
						if err != nil {
							t.Fatal(err)
						}
						var value any
						if err := json.Unmarshal(data, &value); err != nil {
							t.Fatal(err)
						}
						if err := compiled.Validate(value); err != nil {
							t.Fatal(err)
						}
						if name == "eth_signTransaction" && i == 1 {
							for _, missing := range []string{"raw", "tx", "signature"} {
								var invalid map[string]any
								if err := json.Unmarshal(data, &invalid); err != nil {
									t.Fatal(err)
								}
								if missing == "signature" {
									tx := invalid["tx"].(map[string]any)
									delete(tx["signatures"].([]any)[0].(map[string]any), missing)
								} else {
									delete(invalid, missing)
								}
								if err := compiled.Validate(invalid); err == nil {
									t.Fatalf("accepted signed result without %s", missing)
								}
							}
						}
					})
				}
			}
		}
	}

	sign := generator.methods["eth_signTransaction"]["examples"].([]any)[1].(object)
	send := generator.methods["eth_sendTransaction"]["examples"].([]any)[1].(object)
	request := sign["params"].([]any)[0].(object)["value"].(object)
	if !reflect.DeepEqual(request, send["params"].([]any)[0].(object)["value"]) {
		t.Fatal("sign and send requests differ")
	}
	result := sign["result"].(object)["value"].(object)
	tx := result["tx"].(object)
	for key, value := range request {
		if key != "signatures" && !reflect.DeepEqual(value, tx[key]) {
			t.Fatalf("signing changed %s", key)
		}
	}
	signatures := tx["signatures"].([]any)
	placeholders := request["signatures"].([]any)
	if len(signatures) != 1 || len(placeholders) != 1 {
		t.Fatal("expected one signature")
	}
	signature := signatures[0].(object)
	for key, value := range placeholders[0].(object) {
		if !reflect.DeepEqual(value, signature[key]) {
			t.Fatalf("signing changed signature %s", key)
		}
	}
	decode := func(value any) []byte {
		if value == nil {
			return nil
		}
		b, err := hexutil.Decode(value.(string))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	quantity := func(value any) uint64 {
		n, err := hexutil.DecodeUint64(value.(string))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	var frames []any
	for _, item := range tx["frames"].([]any) {
		frame := item.(object)
		frames = append(frames, []any{quantity(frame["mode"]), quantity(frame["flags"]), decode(frame["target"]), []any{quantity(frame["executionGas"]), quantity(frame["stateGas"])}, quantity(frame["value"]), decode(frame["data"])})
	}
	var hashes [][]byte
	for _, hash := range tx["blobVersionedHashes"].([]any) {
		hashes = append(hashes, decode(hash))
	}
	wireSignature := decode(signature["signature"])
	sig := []any{quantity(signature["scheme"]), decode(signature["signer"]), decode(signature["msg"]), wireSignature}
	envelope := []any{quantity(tx["chainId"]), quantity(tx["nonce"]), decode(tx["from"]), frames, []any{sig}, []any{quantity(tx["maxPriorityFeePerGas"]), quantity(tx["maxFeePerGas"]), quantity(tx["maxFeePerBlobGas"])}, hashes}
	encode := func() []byte {
		encoded, err := rlp.EncodeToBytes(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte{byte(quantity(tx["type"]))}, encoded...)
	}
	raw := decode(result["raw"])
	if !bytes.Equal(encode(), raw) {
		t.Fatal("raw transaction differs from signed JSON envelope")
	}
	if !bytes.Equal(crypto.Keccak256(raw), decode(send["result"].(object)["value"])) {
		t.Fatal("submission hash differs from signed transaction hash")
	}
	if quantity(signature["scheme"]) != 1 || len(decode(signature["msg"])) != 0 || len(wireSignature) != 65 {
		t.Fatal("expected canonical secp256k1 signature")
	}
	// Empty-message signature bytes are cleared for the canonical signing hash.
	sig[3] = []byte{}
	digest := crypto.Keccak256(encode())
	// EIP-8141 encodes v before r and s; SigToPub expects v last.
	recoverySignature := append(append([]byte{}, wireSignature[1:]...), wireSignature[0])
	publicKey, err := crypto.SigToPub(digest, recoverySignature)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(crypto.PubkeyToAddress(*publicKey).Bytes(), decode(signature["signer"])) {
		t.Fatal("signature does not recover the declared signer")
	}
}
