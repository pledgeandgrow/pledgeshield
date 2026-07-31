export interface ScanOptions {
  cve?: boolean;
  format?: 'text' | 'json' | 'html' | 'sarif' | 'markdown';
  minSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  offline?: boolean;
}

export declare function runScan(options: ScanOptions): Promise<string>;
export declare function scanSync(options: ScanOptions): string;
