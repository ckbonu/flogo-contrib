# Azure Device Twin
This activity allows you to update a device shadow on AzureIotHub.

## Installation

```bash
flogo install github.com/ckbonu/flogo-contrib/tree/master/activity/azuredevicetwin
```
Link for flogo web:
```
https://github.com/ckbonu/flogo-contrib/tree/master/activity/azuredevicetwin
```

## Schema
Inputs and Outputs:

```json
"inputs":[
    {
      "name": "thingName",
    "type": "string",
    "required": true
  },
    {
      "name": "ConnectionString",
      "type": "string"
    }
  ],
  "outputs": [
    {
      "name": "desired",
      "type": "string"
    },
    {
      "name": "reported",
      "type": "params"
    }
  ]
```
## Inputs
| Input                          | Description    |
|:-------------------------------|:---------------|
| Connection String               | Your Azure IOT ConectionString.It would be something similar to `'HostName=HomeAutoHub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=0JE8ig33UrJNzLbZHn8B2rpT66LYmNzZ9JWEYhlEJJo='`.            |

## Ouputs
                |