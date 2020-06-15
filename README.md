Validations
------------------------------------------------
Can be modified/updated/removed as required

- Username:
  - Containers letters only
  - Must be at least 3 characters
  - Cannot be empty
- Password:
  - Cannot be empty
  - Must be at least 8 characters
  - Must contain a mixture of upper/lower case, numbers and symbols
  - Confirm password must match
- Mobile Auth code:
  - Cannot be empty
  - Must be at least 8 characters
  - Must contain 2 letters and 6 digits, e.g. AB 123 456
- Smartcard pin:
  - Cannot be empty
  - Must be at least 4 digits
  - Must contain digits only

Error Checks
------------------------------------------------
- Username not found
- Incorrect mobile authentication code
- Username and smartcard does not match
- Failed to validate smartcard
- Failed to get data from server
- Connection timed out
- Cannot connect to service
- Bad Request
- No smartcard reader detected
- No smartcard detected
- Failed to read from smartcard
- Failed to retreive certificate from smartcard
- Incorrect pin

Configure Python Web Server URL
------------------------------------------------
- Change backendUrl in ./src/WinLoginPassReset.ini
- Currently set to http://127.0.0.1:5001

Build
------------------------------------------------
- Install visual studio 2017
- Open the .sln file
- Change to release and x64 under Project/Properties Configuration and Configuration Manager
- Add include path (./src/include/curl) under Project/Properties/VC++ Directories/Include Directories
- Add lib path (./src/lib/) under Project/Properties/VC++ Directories/Library Directories
- Build solution

Install
------------------------------------------------
- Copy the following files to C:\Windows\System32
  - dll file ./src/x64/release/WinLoginPassReset.dll
  - dll file under ./src/bin/libcurl.dll
  - ini file ./src/WinLoginPassReset.ini
- Run .\register.reg to install

Uninstall
------------------------------------------------
- Run .\unregister.reg to uninstall
- Delete the dll files added under the install step

TODO
------------------------------------------------
- Clean up backend code (new changes only)

Windows login screen image
------------------------------------------------
- tileimage.bmp will be shown on the login screen this can be updated as required

Diagrams
------------------------------------------------
Under ./diagrams

- Flow:
![Flow](/diagrams/flow.png)

- Diagram:
![Diagram](/diagrams/passReset.png)

