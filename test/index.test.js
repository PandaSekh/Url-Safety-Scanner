require("dotenv").config();
import Scanner from "url-safety-scanner";
let scanner;

beforeAll(async () => {
	return (scanner = await Scanner(
		{
			apiKey: process.env.API_KEY,
			clientId: process.env.CLIENT_ID,
		},
		true
	));
});

test("With no config it should error", () => {
	const consoleSpy = jest.spyOn(console, "error");
	Scanner();
	expect(consoleSpy).toHaveBeenCalledTimes(1);
});

test("With invalid API Key it should error", () => {
	const consoleSpy = jest.spyOn(console, "error");
	Scanner({
		apiKey: "invalidKey",
		clientId: process.env.CLIENT_ID,
	});
	expect(consoleSpy).toHaveBeenCalled();
});

test("Sync Scanner with cached threatLists", async () => {
	const syncScanner = Scanner(
		{
			apiKey: process.env.API_KEY,
			clientId: process.env.CLIENT_ID,
		},
		false
	);
	return syncScanner.scan("google.com").then(data => {
		expect(data).toStrictEqual([]);
	});
});

test("Check a single safe url", async () => {
	return scanner.scan("google.com").then(data => {
		expect(data).toStrictEqual([]);
	});
});

test("Check multiple safe urls", async () => {
	return scanner
		.scan(["google.com", "amazon.com", "github.com"])
		.then(data => {
			expect(data).toStrictEqual([]);
		});
});

test("Check malicious url", async () => {
	return scanner
		.scan("http://malware.testing.google.test/testing/malware/")
		.then(data => {
			expect(data).toStrictEqual([
				"http://malware.testing.google.test/testing/malware/",
			]);
		});
});

test("Check mixed urls", async () => {
	return scanner
		.scan([
			"google.com",
			"http://malware.testing.google.test/testing/malware/",
			"amazon.com",
			"github.com",
		])
		.then(data => {
			expect(data).toStrictEqual([
				"http://malware.testing.google.test/testing/malware/",
			]);
		});
});

test("Get only safe urls", async () => {
	return scanner
		.getSafeUrls([
			"google.com",
			"http://malware.testing.google.test/testing/malware/",
			"amazon.com",
			"github.com",
		])
		.then(data => {
			expect(data).toEqual(["google.com", "amazon.com", "github.com"]);
		});
});

test("Check if a single url is safe with a boolean return", async () => {
	return scanner.isSafe("google.com").then(res => {
		expect(res).toBeTruthy();
	});
});

test("Check if a single url is unsafe with a boolean return", async () => {
	return scanner
		.isSafe("http://malware.testing.google.test/testing/malware/")
		.then(res => {
			expect(res).toBeFalsy();
		});
});
