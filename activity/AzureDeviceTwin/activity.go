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
	ivazureEndpoint = "ConnectionString"
	ivDesired     = "desired"
	ivReported    = "reported"

	ovResult = "result"
)
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

	req := &ShadowRequest{State: &ShadowState{}}

	if context.GetInput(ivDesired) != nil {
		desired := context.GetInput(ivDesired).(map[string]string)
		req.State.Desired = desired
	}

	if context.GetInput(ivReported) != nil {
		reported := context.GetInput(ivReported).(map[string]string)
		req.State.Reported = reported
	}

	return true, nil
}
