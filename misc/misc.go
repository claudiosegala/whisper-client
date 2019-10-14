package misc

import (
	"encoding/json"
	"github.com/labbsr0x/goh/gohclient"
	"github.com/labbsr0x/goh/gohtypes"
	"net/http"
)

func RetrieveHydraURLs(baseURL string) (string, string) {
	httpClient, err := gohclient.New(nil, baseURL)
	gohtypes.PanicIfError("Unable to create a client", http.StatusInternalServerError, err)

	httpClient.ContentType = "application/x-www-form-urlencoded"
	httpClient.Accept = "application/json"

	resp, data, err := httpClient.Get("/hydra")
	if err != nil || resp == nil || resp.StatusCode != 200 {
		gohtypes.Panic("Unable to retrieve the hydra urls", http.StatusInternalServerError)
	}

	var result = make(map[string]string)

	err = json.Unmarshal(data, &result)
	gohtypes.PanicIfError("Unable to unmarshal json", http.StatusInternalServerError, err)

	return result["hydraAdminUrl"], result["hydraPublicUrl"]
}
