package cloudsec

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"strings"
)

func requestedIaCFilters(query lc.Dict) lc.Dict {
	out := lc.Dict{}
	for _, key := range []string{"has_iac_origin", "iac_attribution"} {
		if value, ok := query[key]; ok {
			out[key] = value
		}
	}
	return out
}

func requireIaCReceipt(query lc.Dict, receipt interface{}) error {
	expected := requestedIaCFilters(query)
	if len(expected) == 0 {
		return nil
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("invalid IaC selectors")
	}
	got, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(want, got) {
		return fmt.Errorf("IaC query selectors were not acknowledged by this server version")
	}
	return nil
}

func checkIaCCSVReceipt(query lc.Dict, raw string) (string, error) {
	if len(requestedIaCFilters(query)) == 0 {
		return raw, nil
	}
	const prefix = "# lc_iac_filters_v1="
	line, body, ok := strings.Cut(raw, "\n")
	if !ok || len(line) > 1024 || !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("IaC query selectors were not acknowledged by this server version")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(line, prefix), "\r"))
	var receipt map[string]interface{}
	if err != nil || json.Unmarshal(decoded, &receipt) != nil {
		return "", fmt.Errorf("invalid IaC query receipt")
	}
	if err := requireIaCReceipt(query, receipt); err != nil {
		return "", err
	}
	return body, nil
}
