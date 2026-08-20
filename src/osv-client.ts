import type {OsvVulnerability} from './map.ts';

export interface PackageQuery {
	name: string;
	version: string;
}

export interface QueryResult {
	package: PackageQuery;
	vulns: OsvVulnerability[];
}

const ENDPOINT = 'https://api.osv.dev/v1/querybatch';

type FetchFn = (input: Request | string, init?: RequestInit) => Promise<Response>;

export async function queryOSV(
	packages: PackageQuery[],
	fetchFn: FetchFn = fetch,
): Promise<QueryResult[]> {
	const body = {
		queries: packages.map(p => ({version: p.version, package: {name: p.name, ecosystem: 'npm'}})),
	};

	const res = await fetchFn(ENDPOINT, {
		method: 'POST',
		headers: {'content-type': 'application/json'},
		body: JSON.stringify(body),
	});

	if (!res.ok) {
		throw new Error(`OSV query failed with status ${res.status}`);
	}

	let data: {results?: Array<{vulns?: OsvVulnerability[]}>};
	try {
		data = (await res.json()) as typeof data;
	} catch {
		throw new Error('OSV returned a malformed response');
	}

	if (!Array.isArray(data.results)) {
		throw new Error('OSV returned a malformed response');
	}

	return packages.map((pkg, i) => ({
		package: pkg,
		vulns: data.results?.[i]?.vulns ?? [],
	}));
}
