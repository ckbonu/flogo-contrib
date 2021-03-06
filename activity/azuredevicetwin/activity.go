package azuredevicetwin

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

var log = logger.GetLogger("activity-tibco-rest")

const (
	ivDeviceName       = "DeviceName"
	ivConnectionString = "ConnectionString"
	ivReported         = "reported"

	maxIdleConnections int = 100
	requestTimeout     int = 10
	tokenValidSecs     int = 3600

	ovResult = "result"
)

type sharedAccessKey = string
type sharedAccessKeyName = string
type hostName = string
type deviceID = string

// IotHubHTTPClient is a simple client to connect to Azure IoT Hub
type IotHubHTTPClient struct {
	sharedAccessKeyName sharedAccessKeyName
	sharedAccessKey     sharedAccessKey
	hostName            hostName
	deviceID            deviceID
	client              *http.Client
}

// MyActivity is a stub for your Activity implementation
type azureDT struct {
	metadata *activity.Metadata
}

// NewActivity creates a new activity
func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &azureDT{metadata: metadata}
}

// Metadata implements activity.Activity.Metadata
func (a *azureDT) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements api.Activity.Eval - Invokes a Azure Iot Shadow Update
func (a *azureDT) Eval(context activity.Context) (done bool, err error) {

	DeviceName := context.GetInput(ivDeviceName).(string)
	ConnectionString := context.GetInput(ivConnectionString).(string)
	client, err := NewIotHubHTTPClientFromConnectionString(ConnectionString)
	if err != nil {
		log.Error("Error creating http client from connection string", err)
	}

	resp, status := client.getDeviceTwin(DeviceName)

	log.Info("status", status)
	context.SetOutput(ovResult, resp)
	//context.SetOutput(ovResult, status)
	return true, nil

}

////////////////////////////////////////////////////////////////////////////////////////
// Utils

// NewIotHubHTTPClientFromConnectionString creates new client from connection string
func parseConnectionString(ConnectionString string) (hostName, sharedAccessKey, sharedAccessKeyName, deviceID, error) {
	url, err := url.ParseQuery(ConnectionString)
	if err != nil {
		return "", "", "", "", err
	}

	h := tryGetKeyByName(url, "HostName")
	kn := tryGetKeyByName(url, "SharedAccessKeyName")
	k := tryGetKeyByName(url, "SharedAccessKey")
	d := tryGetKeyByName(url, "DeviceId")

	return hostName(h), sharedAccessKey(k), sharedAccessKeyName(kn), deviceID(d), nil
}

func tryGetKeyByName(v url.Values, key string) string {
	if len(v[key]) == 0 {
		return ""
	}

	return strings.Replace(v[key][0], " ", "+", -1)
}

// NewIotHubHTTPClient is a constructor of IutHubClient
func NewIotHubHTTPClient(hostName string, sharedAccessKeyName string, sharedAccessKey string, deviceID string) *IotHubHTTPClient {
	return &IotHubHTTPClient{
		sharedAccessKeyName: sharedAccessKeyName,
		sharedAccessKey:     sharedAccessKey,
		hostName:            hostName,
		deviceID:            deviceID,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: maxIdleConnections,
			},
			Timeout: time.Duration(requestTimeout) * time.Second,
		},
	}
}

// NewIotHubHTTPClientFromConnectionString creates new client from connection string
func NewIotHubHTTPClientFromConnectionString(connectionString string) (*IotHubHTTPClient, error) {
	h, k, kn, d, err := parseConnectionString(connectionString)
	if err != nil {
		return nil, err
	}

	return NewIotHubHTTPClient(h, kn, k, d), nil
}

// IsDevice tell either device id was specified when client created.
// If device id was specified in connection string this will enabled device scoped requests.
func (c *IotHubHTTPClient) IsDevice() bool {
	return c.deviceID != ""
}

func (c *IotHubHTTPClient) getDeviceTwin(deviceID string) (string, string) {
	url := fmt.Sprintf("%s/twins/%s/?api-version=2016-11-14", c.hostName, deviceID)
	return c.performRequest("GET", url, "")
}

func (c *IotHubHTTPClient) buildSasToken(uri string) string {
	timestamp := time.Now().Unix() + int64(3600)
	encodedURI := template.URLQueryEscaper(uri)

	toSign := encodedURI + "\n" + strconv.FormatInt(timestamp, 10)

	binKey, _ := base64.StdEncoding.DecodeString(c.sharedAccessKey)
	mac := hmac.New(sha256.New, []byte(binKey))
	mac.Write([]byte(toSign))

	encodedSignature := template.URLQueryEscaper(base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	if c.sharedAccessKeyName != "" {
		return fmt.Sprintf("SharedAccessSignature sig=%s&se=%d&skn=%s&sr=%s", encodedSignature, timestamp, c.sharedAccessKeyName, encodedURI)
	}

	return fmt.Sprintf("SharedAccessSignature sig=%s&se=%d&sr=%s", encodedSignature, timestamp, encodedURI)
}

func (c *IotHubHTTPClient) performRequest(method string, uri string, data string) (string, string) {
	token := c.buildSasToken(uri)
	//log.("%s https://%s\n", method, uri)
	//log.Printf(data)
	req, _ := http.NewRequest(method, "https://"+uri, bytes.NewBufferString(data))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "golang-iot-client")
	req.Header.Set("Authorization", token)

	//log.Println("Authorization:", token)

	if method == "DELETE" {
		req.Header.Set("If-Match", "*")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		log.Error(err)
	}

	// read the entire reply to ensure connection re-use
	text, _ := ioutil.ReadAll(resp.Body)

	io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()

	return string(text), resp.Status
}
