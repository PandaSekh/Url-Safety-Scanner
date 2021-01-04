// Type definitions for url-safety-scanner 1.0.2
// Project: https://github.com/PandaSekh/Url-Safety-Scanner
// Definitions by: Alessio Franceschi <https://github.com/PandaSekh/>

declare class Scanner {
  constructor(config: ScannerConfig, updateThreatInfo: boolean = false);

  getThreatInfos(): Promise<void>;
  isSafe(): Promise<boolean>;
  scan(): Promise<Array<string>>;
  getSafeUrls(): Promise<Array<string>>
}

declare function ScannerConstructor(config: ScannerConfig, updateThreatInfo: boolean = false): Scanner | Promise<Scanner>;

interface ScannerConfig {
  apiKey: string;
  clientId: string;
  clientVersion?: string;
}

export as namespace Scanner