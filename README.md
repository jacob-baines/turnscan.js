# turnscan.js
Scanning LAN hosts from Chrome using ICE servers. Try it for yourself here:

https://jacob-baines.github.io/turnscan.js/index.html

The demo page will categorize a port as "Open", "Closed", or "?" (filtered). There is some complication due to Chrome's mitigation of the WebRTC private IP leak. For a full explanation read this:

https://medium.com/tenable-techblog/using-webrtc-ice-servers-for-port-scanning-in-chrome-ce17b19dd474

Note that this is *Chrome* only, and won't work for the iPhone version. It's been tested on:

* Chrome 79.0.3945.79 for OS X
* Chrome 79.0.3945.88 for OS X
* Chromium 79.0.3945.79 for Ubuntu
* Chrome 79.0.3945.79 for Windows 10
* Chrome 79.0.3945.88 for Windows 10

