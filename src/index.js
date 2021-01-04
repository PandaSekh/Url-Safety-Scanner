const fetch = require("node-fetch");
const { THREAT_INFO } = require("./threatInfo");

/**
 * Constructor for the Scanner Object
 * @access private
 */
class Scanner {
	constructor(config, updateThreatInfo = false) {
		if (!(this instanceof Scanner)) {
			return new Scanner(config);
		}

		this.API_KEY = config.apiKey;

		this.CLIENT_INFO = {
			clientId: config.clientId,
			clientVersion: config.clientVersion || "1.0.0",
		};

		this.threatTypes = updateThreatInfo
			? new Set()
			: THREAT_INFO.threatTypes;
		this.platformTypes = updateThreatInfo
			? new Set()
			: THREAT_INFO.platformTypes;
		this.threatEntryTypes = updateThreatInfo
			? new Set()
			: THREAT_INFO.threatEntryTypes;
	}

	getThreatInfos() {
		this.threatTypes = new Set();
		this.platformTypes = new Set();
		this.threatEntryTypes = new Set();

		return new Promise((resolve, reject) => {
			fetch(
				`https://safebrowsing.googleapis.com/v4/threatLists?key=${this.API_KEY}`,
				{
					method: "GET",
					headers: { "Content-Type": "application/json" },
				}
			)
				.then(res => {
					if (res.ok) {
						return res.json();
					} else throw new Error("Can't update threat list");
				})
				.then(jsonRes => {
					jsonRes.threatLists.forEach(threat => {
						this.threatTypes.add(threat.threatType);
						this.platformTypes.add(threat.platformType);
						this.threatEntryTypes.add(threat.threatEntryType);
					});
					resolve();
				})
				.catch(err => {
					console.error(err);
					reject();
				});
		});
	}

	scan = urls => {
		const threatEntries = [];
		if (!Array.isArray(urls)) {
			urls = [urls];
		}
		urls.forEach(url => threatEntries.push({ url: url }));
		const client = this.CLIENT_INFO;

		return new Promise((resolve, reject) => {
			fetch(
				`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${this.API_KEY}`,
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						client: client,
						threatInfo: {
							threatTypes: Array.from(this.threatTypes),
							platformTypes: Array.from(this.platformTypes),
							threatEntryTypes: Array.from(this.threatEntryTypes),
							threatEntries: threatEntries,
						},
					}),
				}
			)
				.then(r => r.json())
				.then(j => {
					const response = new Set();
					if (Object.keys(j).length > 0) {
						j.matches?.forEach(match => {
							response.add(match.threat.url);
						});
					}
					resolve(Array.from(response));
				})
				.catch(err => {
					console.error(err);
					reject();
				});
		});
	};

	isSafe = async url => {
		const scan = await this.scan(url);
		return !(scan.length > 0 && scan[0] === url);
	};

	getSafeUrls = async urls => {
		const unsafe = await this.scan(urls);
		const safe = [];
		urls.forEach(u => {
			if (!unsafe.includes(u)) {
				safe.push(u);
			}
		});
		return safe;
	};
}

function ScannerConstructor(config, updateThreatInfo = false) {
	if (!config) {
		console.error("Link Scanner: You need to pass a configuration object");
	} else if (!updateThreatInfo) {
		return new Scanner(config, updateThreatInfo);
	} else {
		return new Promise(async (resolve, reject) => {
			try {
				const scanner = new Scanner(config, updateThreatInfo);
				await scanner.getThreatInfos();
				return resolve(scanner);
			} catch (err) {
				console.error("Couldn't initialize Scanner");
				reject();
			}
		});
	}
}

module.exports = ScannerConstructor;
