export = ScannerConstructor;
/**
 *
 * @param {Config} config
 * @param {boolean} [updateThreatInfo=false]
 */
declare function ScannerConstructor(config: {
    apiKey: string;
    clientId: string;
    clientVersion: string;
}, updateThreatInfo?: boolean): Promise<any> | Scanner;
declare class Scanner {
    /**
     * @typedef {Object} Config
     * @property {string} apiKey
     * @property {string} clientId
     * @property {string} clientVersion
     */
    /**
     *
     * @param {Config} configuration
     * @param {boolean} updateThreatInfo
     */
    constructor(Config: any, updateThreatInfo: boolean);
    API_KEY: any;
    CLIENT_INFO: {
        clientId: any;
        clientVersion: any;
    };
    threatTypes: string[] | Set<any>;
    platformTypes: string[] | Set<any>;
    threatEntryTypes: string[] | Set<any>;
    getThreatInfos(): Promise<any>;
    /**
     *
     * @param {Array<string>} urls
     * @returns {Array<string>} unsafeUrls
     */
    scan: (urls: Array<string>) => Array<string>;
    /**
     *
     * @param {string} url
     * @returns {boolean} isUrlSafe
     */
    isSafe: (url: string) => boolean;
    /**
     *
     * @param {Array<string>} urls
     * @returns {Array<string>} safeUrls
     */
    getSafeUrls: (urls: Array<string>) => Array<string>;
}
