package AzureDeviceTwin

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"

	MQTT "github.com/eclipse/paho.mqtt.golang"
)
var log = logger.GetLogger("activity-tibco-rest")

const (
	ivDeviceName   = "DeviceName"
	ivazureEndpoint = "azureEndpoint"
	ivConnectionString = "ConnectionString"
	ivDesired     = "desired"
	ivReported    = "reported"

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
func (a *azureDT) Eval(context activity.Context) (done bool, err error)  {

	DeviceName := context.GetInput(ivDeviceName).(string)
	ConnectionString := context.GetInput(ivazureEndpoint).(string)

}
func parseConnectionString(connString string) (hostName, sharedAccessKey, sharedAccessKeyName, deviceID, error) {
	url, err := url.ParseQuery(connString)
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

	log.Debugf("Shadow Request: %s", string(reqJSON))

	brokerURI := fmt.Sprintf("ssl://%s:%d", azureEndpoint, 8883)
	log.Debugf("Broker URI: %s", brokerURI)

	tlsConfig := NewTLSConfig(DeviceName)

	opts := MQTT.NewClientOptions()
	opts.AddBroker(brokerURI)
	opts.SetClientID(context.FlowDetails().ID())
	opts.SetTLSConfig(tlsConfig)

	// Start the connection
	client := MQTT.NewClient(opts)
	defer client.Disconnect(250)

	token := client.Connect()

	if token.Wait() && token.Error() != nil {
		log.Errorf("Error connecting to '%s': %s", brokerURI, token.Error().Error())
		return false, activity.NewError(token.Error().Error(), "", nil)
	}

	thingUpdate := fmt.Sprintf("$azure/things/%s/shadow/update", DeviceName)
	Publish(client, thingUpdate, 1, string(reqJSON))

	return true, nil
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
////////////////////////////////////////////////////////////////////////////////////////
// Utils

// Publish publishes a client message
func Publish(client MQTT.Client, topic string, qos int, input string) error {
	token := client.Publish(topic, byte(qos), false, input)
	if token.Wait() && token.Error() != nil {
		log.Error(token.Error())
		return token.Error()
	}
	return nil
}

// NewTLSConfig creates a TLS configuration for the specified 'thing'
func NewTLSConfig(thingName string) *tls.Config {
	// Import root CA
	certpool := x509.NewCertPool()
	pemCerts, err := ioutil.ReadFile("things/root-CA.pem.crt")
	if err == nil {
		certpool.AppendCertsFromPEM(pemCerts)
	}

	thingDir := "things/" + thingName + "/"

	// Import client certificate/key pair for the specified 'thing'
	cert, err := tls.LoadX509KeyPair(thingDir+"device.pem.crt", thingDir+"device.pem.key")
	if err != nil {
		panic(err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		RootCAs:            certpool,
		ClientAuth:         tls.NoClientCert,
		ClientCAs:          nil,
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	}
}

// ShadowRequest is a simple structure representing a Aws Shadow Update Request
type ShadowRequest struct {
	State *ShadowState `json:"state"`
}

// ShadowState is the state to be updated
type ShadowState struct {
	Desired  map[string]string `json:"desired,omitempty"`
	Reported map[string]string `json:"reported,omitempty"`
