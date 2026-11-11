package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func decodeBoundedJSONResponse(response *http.Response, maxBytes int64, destination any) error {
	if response == nil || response.Body == nil || maxBytes < 0 {
		return errors.New("invalid JSON response")
	}
	if response.ContentLength > maxBytes {
		return errors.New("JSON response exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return errors.New("JSON response could not be read")
	}
	if int64(len(data)) > maxBytes {
		return errors.New("JSON response exceeds size limit")
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return errors.New("JSON response is invalid")
	}
	return nil
}
