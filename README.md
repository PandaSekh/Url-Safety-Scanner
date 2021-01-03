# Url Safety Scanner
![Node.js CI](https://github.com/PandaSekh/link-scanner/workflows/Node.js%20CI/badge.svg)

Small Node.js utility to check for the safety of URLs.

Working on the Documentation.
## Usage

This library is based on [Google Safe Browsing](https://developers.google.com/safe-browsing/v4), so it requires a Google API Key, [see here](https://cloud.google.com/docs/authentication/api-keys?hl=en&ref_topic=6262490&visit_id=637452868400701187-4266388275&rd=1).



Import the library and initialize it:
```
const  Scanner = require("safe-url-scanner");

// With updated threat list 
const myScanner = await Scanner({
		apiKey:  #GOOGLE_API_KEY (required),
		clientId:  #UNIQUE_IDENTIFIER (required),
		clientVersion: #CLIENT_VERSION (optional)
	}, true)

// With default threat list
const myScanner = Scanner({
	apiKey:  #GOOGLE_API_KEY (required),
	clientId:  #UNIQUE_IDENTIFIER (required),
	clientVersion: #CLIENT_VERSION (optional)
})
```

By default the Scanner object is initialized synchronously and will use the default threat lists (not a actual list of threat, just a list of what we consider a threat. By default it's everything). By passing a *true* boolean, we can create a Scanner with updated threat lists, but in this case the creation returns a Promise.

After initialization, the client expose two methods: **scan** and **getSafeUrls**.
Both accepts an **Array** of urls (String). *Scan* returns an Array of urls considered malicious, while *getSafeUrls* will return an Array containing only safe urls. 

Examples: 
```
myScanner.scan(["github.com"])
	.then(data => console.log(data));
	// [] 
	
myScanner.scan(["github.com", "badwebsite.com"])
	.then(data => console.log(data));
	// ["badwebsite.com"] 
	
myScanner.getSafeUrls(["github.com", "badwebsite.com"])
	.then(data => console.log(data));
	// ["github.com"] 
```
