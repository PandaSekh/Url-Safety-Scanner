export = ScannerConstructor;
/**
 *
 * @param {Config} config
 * @param {boolean} [updateThreatInfo=false]
 */
declare function ScannerConstructor(config: {
    /**
     * Google API KEY
     */
    apiKey: string;
    /**
     * Unique identifier of the client
     */
    clientId: string;
    /**
     * of the client
     */
    Version: string;
}, updateThreatInfo?: boolean): Promise<any> | Scanner;
declare class Scanner {
    /**
     * @typedef {Object} Config
     * @property {string} apiKey Google API KEY
     * @property {string} clientId Unique identifier of the client
     * @property {string} Version of the client
     */
    /**
     *
     * @param {Config} configuration object
     * @param {boolean} updateThreatInfo should the threat info be updated
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
     * @returns {Array<string>} unsafe urls
     */
    scan: (urls: Array<string>) => Array<string>;
    /**
     *
     * @param {string} url
     * @returns {boolean} is the url safe
     */
    isSafe: (url: string) => boolean;
    /**
     *
     * @param {Array<string>} urls
     * @returns {Array<string>} safe urls
     */
    getSafeUrls: (urls: Array<string>) => Array<string>;
}
