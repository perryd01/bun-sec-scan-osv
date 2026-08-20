import {queryOSV, type QueryResult} from './osv-client.ts';
import {vulnToAdvisory} from './map.ts';

type QueryFn = (queries: Array<{name: string; version: string}>) => Promise<QueryResult[]>;

export interface ScannerDeps {
	query: QueryFn;
}

export function createScanner(deps: Partial<ScannerDeps> = {}): Bun.Security.Scanner {
	const query = deps.query ?? queryOSV;

	return {
		version: '1',
		async scan({packages}) {
			const queries = packages.map(p => ({name: p.name, version: p.version}));
			const results = await query(queries);

			const advisories: Bun.Security.Advisory[] = [];
			for (const {package: pkg, vulns} of results) {
				for (const vuln of vulns) {
					advisories.push(vulnToAdvisory(pkg.name, vuln));
				}
			}
			return advisories;
		},
	};
}

export const scanner = createScanner();
