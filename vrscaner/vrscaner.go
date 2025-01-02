package vrscaner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type VTScaner struct {
	token string
}

func NewVTScaner(token string) *VTScaner {
	return &VTScaner{token: token}
}

type Report struct {
	UrlID    string    `json:"url_id"`
	Results  []Result  `json:"results"`
	ScanDate time.Time `json:"scan_date"`
}

func NewReport(urlID string, data time.Time) *Report {
	return &Report{UrlID: urlID, Results: make([]Result, 0), ScanDate: data}
}

type Result struct {
	Category    string `json:"category"`
	Engine_name string `json:"engine_name"`
	Result      string `json:"result"`
}

func NewResult(category string, engine_name string, result string) *Result {
	return &Result{Category: category, Engine_name: engine_name, Result: result}
}

// Get report by URLId
func (vtscaner *VTScaner) GetReport(context context.Context, urlID string) (*Report, error) {

	url := "https://www.virustotal.com/api/v3/analyses/" + urlID

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", vtscaner.token)

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	var result map[string]interface{}
	err = json.Unmarshal([]byte(body), &result)

	if err != nil {
		return nil, err
	}

	mapDataError := errors.New("data is not a map")

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return nil, mapDataError
	}

	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return nil, mapDataError
	}

	ScanData := time.Unix(int64(attributes["date"].(float64)), 0)

	results, ok := attributes["results"].(map[string]interface{})
	if !ok {
		return nil, mapDataError
	}

	report := NewReport(urlID, ScanData)

	mapForScoreRating := map[string]string{}

	for _, r := range results {

		rResult := r.(map[string]interface{})["result"].(string)
		rCategory := r.(map[string]interface{})["category"].(string)
		rEngine_name := r.(map[string]interface{})["engine_name"].(string)

		report.Results = append(report.Results, *NewResult(rCategory, rEngine_name, rResult))
		mapForScoreRating[rEngine_name] = rResult
	}

	return report, nil
}

// Scan URL
func (vtscan *VTScaner) ScanURL(context context.Context, scanUrl string) (string, error) {

	url := "https://www.virustotal.com/api/v3/urls"

	payload := strings.NewReader("url=" + scanUrl)

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", vtscan.token)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	mapDataError := errors.New("data is not a map")

	body, _ := io.ReadAll(res.Body)

	var result map[string]interface{}
	err = json.Unmarshal([]byte(body), &result)

	if err != nil {
		return "", err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return "", mapDataError
	}

	return data["id"].(string), nil
}

// POST reanalyze URL
func (vtscan *VTScaner) ReanalyzeURl(context context.Context, url string) (string, error) {
	// TODO доделать до релизной версии
	return "", nil
}

// конвертировать в Json
func ToJson(data interface{}) ([]byte, error) {

	jsonData, err := json.Marshal(data)

	if err != nil {
		return nil, err
	}

	return jsonData, nil
}
