export interface OsvSeverity {
	type: string;
	score: string;
}

export interface OsvReference {
	type: string;
	url: string;
}

export interface OsvVulnerability {
	id?: string;
	summary?: string;
	details?: string;
	references?: OsvReference[];
	severity?: OsvSeverity[];
}

export interface OsvAdvisory {
	level: 'fatal' | 'warn';
	package: string;
	url: string | null;
	description: string | null;
}

const CVSS_V3_BASE = 7.0;

export function vulnToAdvisory(packageName: string, vuln: OsvVulnerability): OsvAdvisory {
	const scores = (vuln.severity ?? [])
		.filter(s => s.type === 'CVSS_V3')
		.map(s => cvss3Score(s.score))
		.filter((s): s is number => s !== null);

	const maxScore = scores.length > 0 ? Math.max(...scores) : null;

	const url =
		vuln.references && vuln.references.length > 0 ? (vuln.references[0]?.url ?? null) : null;

	return {
		level: maxScore !== null && maxScore >= CVSS_V3_BASE ? 'fatal' : 'warn',
		package: packageName,
		url,
		description: vuln.summary ?? vuln.details ?? null,
	};
}

const AV = {N: 0.85, A: 0.62, L: 0.55, P: 0.2};
const AC = {L: 0.77, H: 0.44};
const PR_UNCHANGED = {N: 0.85, L: 0.62, H: 0.27};
const PR_CHANGED = {N: 0.85, L: 0.68, H: 0.5};
const UI = {N: 0.85, R: 0.62};
const CIA = {H: 0.56, L: 0.22, N: 0};

function cvss3Score(vector: string): number | null {
	const match = vector.match(/CVSS:[0-9.]+(\/.*)/);
	if (!match) return null;

	const parts = new Map<string, string>();
	for (const part of match[1]!.split('/').filter(Boolean)) {
		const [k, v] = part.split(':');
		if (k && v) parts.set(k, v);
	}

	const av = AV[parts.get('AV') as keyof typeof AV];
	const ac = AC[parts.get('AC') as keyof typeof AC];
	const scope = parts.get('S');
	const pr = (scope === 'C' ? PR_CHANGED : PR_UNCHANGED)[
		parts.get('PR') as keyof typeof PR_UNCHANGED
	];
	const ui = UI[parts.get('UI') as keyof typeof UI];
	const c = CIA[parts.get('C') as keyof typeof CIA];
	const i = CIA[parts.get('I') as keyof typeof CIA];
	const a = CIA[parts.get('A') as keyof typeof CIA];

	if (
		av === undefined ||
		ac === undefined ||
		pr === undefined ||
		ui === undefined ||
		c === undefined ||
		i === undefined ||
		a === undefined
	) {
		return null;
	}

	const iss = 1 - (1 - c) * (1 - i) * (1 - a);
	const exploitability = 8.22 * av * ac * pr * ui;

	let impact: number;
	let base: number;
	if (scope === 'C') {
		impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
		base = Math.min(1.08 * (impact + exploitability), 10);
	} else {
		impact = 6.42 * iss;
		base = Math.min(impact + exploitability, 10);
	}

	return Math.ceil(base * 10) / 10;
}
