package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The protocol watch (tools/protocolwatch) checks how the replayed packets would change under a new
// protocol version. It reads them from templates.json; this test keeps that file and the tpl*
// constants in bedrock.go in step.
func TestTemplateDataMatchesConstants(t *testing.T) {
	raw, err := os.ReadFile("../../tools/protocolwatch/templates.json")
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]string
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}

	want := map[string][]byte{
		"NetworkSettingsPacket":     tplNetworkSettings,
		"PlayStatusPacket":          tplPlayStatusOK,
		"PlayStatusPacket#spawn":    tplPlayStatusSpawn,
		"ResourcePacksInfoPacket":   tplPacksInfo,
		"ResourcePackStackPacket":   tplPackStack,
		"JigsawStructureDataPacket": tpl313,
		"VoxelShapesPacket":         tpl337,
		"StartGamePacket":           tplStartGame,
		"ItemRegistryPacket":        tplItemRegistry,
		"ChunkRadiusUpdatedPacket":  tplChunkRadius,
		"CreativeContentPacket":     tpl145,
	}
	if len(data) != len(want) {
		t.Errorf("templates.json has %d entries, bedrock.go %d", len(data), len(want))
	}
	for name, b := range want {
		got, err := hex.DecodeString(data[name])
		if name == "StartGamePacket" {
			// Stored as recorded; the code swaps the world name (see tplStartGame).
			got = bytes.Replace(got, []byte("survival"), []byte("transfer"), 1)
		}
		if err != nil || !bytes.Equal(got, b) {
			t.Errorf("%s: templates.json differs from the constant in bedrock.go\n json %x\n code %x", name, got, b)
		}
	}
}
