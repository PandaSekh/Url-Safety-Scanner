# Url Safety Scanner
![Node.js CI](https://github.com/PandaSekh/Url-Safety-Scanner/workflows/Node.js%20CI/badge.svg)

> Small Node.js utility to check for the safety of URLs.

## Installation
```sh
npm install url-safety-scanner
```
or
```sh
yarn add url-safety-scanner
```

## Usage

This library is based on [Google Safe Browsing](https://developers.google.com/safe-browsing/v4), so it requires a free Google API Key, [get one here](https://cloud.google.com/docs/authentication/api-keys?hl=en&ref_topic=6262490&visit_id=637452868400701187-4266388275&rd=1).

Import the library and initialize the Scanner object:
```js
import Scanner from "url-safety-scanner";

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

## API
### Scanner
```js
Scanner(config: Object, updateThreatInfo:boolean = false) => ScannerConstructor || Promise(ScannerConstructor)
```
Constructor for the Scanner object. If `updateThreatInfo` is true, returns a Promise.

#### Parameters
`config` Configuration object.
```js
const config = {
	apiKey:  #GOOGLE_API_KEY (required),
	clientId:  #UNIQUE_IDENTIFIER (required),
	clientVersion: #CLIENT_VERSION (optional)
}
```

`updateThreatInfo` Should the constructor update the threat info list with the latest information? Defaults to false.
See [Google Safe Browsing Docs](https://developers.google.com/safe-browsing/v4/lists) for infos about the Threat List.
```js
const config = {
	apiKey:  #GOOGLE_API_KEY (required),
	clientId:  #UNIQUE_IDENTIFIER (required),
	clientVersion: #CLIENT_VERSION (optional)
}
```

##### Default Threat List:
The default Threat List includes everything: 
```js
THREAT_INFO = {
	threatTypes: [
		"MALWARE",
		"SOCIAL_ENGINEERING",
		"POTENTIALLY_HARMFUL_APPLICATION",
		"UNWANTED_SOFTWARE",
	],
	platformTypes: [
		"LINUX",
		"OSX",
		"IOS",
		"WINDOWS",
		"CHROME",
		"ALL_PLATFORMS",
		"ANY_PLATFORM",
		"ANDROID",
	],
	threatEntryTypes: ["URL"],
};
```
### isSafe
```js
isSafe(url: String) => Promise<boolean> 
```
`isSafe` returns an Promise<boolean> which resolves to true if the url is safe.

#### Parameters
`url` A String of the url to scan.

#### Returns
`Promise<boolean>` True if url is safe.

Example:
```js
myScanner.isSafe("github.com")
	.then(safe => console.log(safe));
	// true
	
myScanner.isSafe("badwebsite.com")
	.then(safe => console.log(safe));
	// false
```

### scan
```js
scan(urls: Array(String)) => Promise<Array> 
```
`scan` returns an Promise<Array> of urls considered malicious.

#### Parameters
`urls` An Array of urls to scan.

#### Returns
` Promise<Array>` An Array of urls considered malicious.

Example:
```js
myScanner.scan(["github.com"])
	.then(data => console.log(data));
	// [] 
	
myScanner.scan(["github.com", "badwebsite.com"])
	.then(data => console.log(data));
	// ["badwebsite.com"] 
```

### getSafeUrls
```js
getSafeUrls(urls: Array<String>) => Promise<Array>
```
`getSafeUrls` returns an Promise<Array> of urls considered safe.

#### Parameters
`urls` An Array of urls to scan.

#### Returns
` Promise<Array>` An Array of urls considered safe.

Example:
```js
myScanner.getSafeUrls(["github.com", "badwebsite.com"])
	.then(data => console.log(data));
	// ["github.com"] 
```

## License
MIT License
Copyright (c) 2021 Alessio Franceschi