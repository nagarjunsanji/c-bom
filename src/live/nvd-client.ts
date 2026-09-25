import 'dotenv/config';

import type { CveFinding } from '../types';

interface NvdResponse {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      published?: string;
      lastModified?: string;
      metrics?: {
        cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
        cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
      };
    };
  }>;
}

export async function findNvdCves(
  packageName: string,
  options: { apiKey?: string; fetchImpl?: typeof fetch } = {},
): Promise<CveFinding[]> {
  const apiKey = options.apiKey ?? process.env.NVD_API_KEY;
  if (!apiKey) {
    throw new Error('NVD_API_KEY is required for live scanning.');
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(packageName)}&resultsPerPage=20`;
  const response = await fetchImpl(url, { headers: { apiKey } });
  if (!response.ok) {
    throw new Error(`NVD request failed with HTTP ${response.status}.`);
  }
  const payload = (await response.json()) as NvdResponse;
  return (payload.vulnerabilities ?? []).flatMap(({ cve }) => {
    if (!cve?.id) return [];
    const description = cve.descriptions?.find((item) => item.lang === 'en')?.value ?? 'No description provided.';
    const metric = cve.metrics?.cvssMetricV31?.[0]?.cvssData ?? cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    return [{
      id: cve.id,
      description,
      ...(cve.published ? { published: cve.published } : {}),
      ...(cve.lastModified ? { lastModified: cve.lastModified } : {}),
      ...(metric?.baseSeverity ? { severity: metric.baseSeverity } : {}),
      ...(metric?.baseScore !== undefined ? { score: metric.baseScore } : {}),
    }];
  });
}
