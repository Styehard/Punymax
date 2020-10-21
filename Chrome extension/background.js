// Copyright 2020 Maksymilian Jan Szymanski 
// Universidad Carlos III Madrid
// Contributor: Andrés Marín López
//
// Licensed under the Apache License, Version 2.0 (the "License"); 
// you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at 
//
//   http://www.apache.org/licenses/LICENSE-2.0 
//
// Unless required by applicable law or agreed to in writing, 
// software distributed under the License is distributed on an "AS IS" BASIS, 
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
// See the License for the specific language governing permissions and 
// limitations under the License.

chrome.webRequest.onBeforeSendHeaders.addListener(function(details){
        var IDN = ""
        var url = new URL(details.url);
        var expression = /[a-zA-Z0-9-]+/gi;
        var regex = new RegExp(expression);
        blockingResponse = {};
        // CHANGE: following IP for your local device ip
        if(url.hostname != "192.168.56.101" && (url.hostname.includes("xn--") || !url.hostname.match(regex))){
          var xhttp = new XMLHttpRequest();
          xhttp.onreadystatechange = function() {
          if (xhttp.readyState == 4 && xhttp.status == 200 && xhttp.responseText.includes(".")) {
            console.log("Results for: " + url.hostname + "----------" + xhttp.responseText + "----------");
            alert("Be carefull! \nThe website you are trying to access is trying to impersonate: " + xhttp.responseText);
          }
          }
          chrome.storage.sync.get({
            userLanguague: 'es',
            userDetail: 'small',
            userLevel: 0
          }, function(items) {
            // CHANGE: address to your environment
            xhttp.open("GET", "http://localhost/pycgi/PunyMax_analysis.py?url=" + url.hostname + "&verbose=" + items.userDetail + "&permutation=" + items.userLevel,true);
            xhttp.send();
          });
          
        }
        return blockingResponse;
      },
      {urls: [ "*://*/*" ]},['requestHeaders','blocking']);

