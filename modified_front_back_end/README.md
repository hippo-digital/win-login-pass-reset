# Installation Instructions

## Server (Back-end) Install

### Download and install these components

* Python 3.6.2 64-bit (ensure you get the amd64 one)
* Git (latest version)
* PyWin32 https://sourceforge.net/projects/pywin32/files/pywin32/Build%20221/pywin32-221.win-amd64-py3.6.exe/download


### Install source

````
mkdir C:\git
cd C:\git
git clone https://github.com/hippodigital/password-self-service.git


pip install requests pyyaml twilio https://github.com/zakird/pyad/archive/master.zip
````

### Configuration

Update the config file to reflect local environment

The file is: C:\git\password-self-service\password_reset_backend\config.yml

````
---
  directory:

    # Update to reflect the
    dn: CN=Users,DC=hd,DC=local
    fqdn: hd.local

  frontend:
    address: https://10.211.55.2:5000

  sms:
    message: "A reset code has been requested for your account.\n\nIf this was in error contact the service desk on 0113 235 3315.\n\nYour reset code is %s"
    organisation_shortname: RothICT
    twilio_sid: <twilio_sid>
    twilio_authcode: <twilio_authcode>

  redis:
    address: 127.0.0.1
    port: 6379
    db: 0
````



