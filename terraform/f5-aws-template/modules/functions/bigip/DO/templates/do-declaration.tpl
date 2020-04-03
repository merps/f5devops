{
    "schemaVersion": "1.0.0",
    "class": "Device",
    "async": true,
    "Common": {
        "class": "Tenant",
        "hostname": "${bigip_hostname}",
        "myProvisioning": {
            "class": "Provision",
            "ltm": "nominal",
            "asm": "nominal"
        },
        "external": {
            "class": "VLAN",
            "tag": 10,
            "mtu": 1500,
            "interfaces": [
                {
                    "name": "1.1",
                    "tagged": false
                }
            ]
        },
        "internal": {
            "class": "VLAN",
            "tag": 20,
            "mtu": 1500,
            "interfaces": [
                {
                    "name": "1.2",
                    "tagged": false
                }
            ]
        },
        "external-self": {
            "class": "SelfIp",
            "address": "${bigip_external_self_ip}",
            "vlan": "external",
            "allowService": [
                "tcp:443"
            ],
            "trafficGroup": "traffic-group-local-only"
        }
    }
}