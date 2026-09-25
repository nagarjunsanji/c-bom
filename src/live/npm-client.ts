import type { DependencyRecord } from '../types';

interface NpmPackageMetadata {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function packageUrl(name: string, version: string): string {
  const encodedName = name.startsWith('@')
    ? name.split('/').map(encodeURIComponent).join('/')
    : encodeURIComponent(name);
  return `https://registry.npmjs.org/${encodedName}/${encodeURIComponent(version)}`;
}

async function readMetadata(
  dependency: DependencyRecord,
  fetchImpl: typeof fetch,
): Promise<NpmPackageMetadata | undefined> {
  if (dependency.version === 'unknown') return undefined;
  const response = await fetchImpl(packageUrl(dependency.name, dependency.version));
  if (!response.ok) return undefined;
  const value: unknown = await response.json();
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as NpmPackageMetadata;
}

/** Resolves a bounded transitive dependency graph for live analysis only. */
export async function resolveLiveDependencies(
  direct: DependencyRecord[],
  options: { fetchImpl?: typeof fetch; maxDepth?: number } = {},
): Promise<DependencyRecord[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const maxDepth = options.maxDepth ?? 3;
  const result = [...direct];
  const seen = new Set(direct.map((dependency) => dependency.name.toLowerCase()));
  const recordsByName = new Map(result.map((dependency) => [dependency.name.toLowerCase(), dependency]));
  let frontier = direct;

  for (let depth = 0; depth < maxDepth && frontier.length; depth += 1) {
    const metadata = await Promise.all(
      frontier.map(async (dependency) => ({ dependency, value: await readMetadata(dependency, fetchImpl) })),
    );
    const next: DependencyRecord[] = [];

    for (const { dependency: parentDependency, value } of metadata) {
      if (!value) continue;
      const dependencies = { ...value.dependencies, ...value.optionalDependencies };
      for (const [name, declaredVersion] of Object.entries(dependencies)) {
        const key = name.toLowerCase();
        const parent = recordsByName.get(key);
        if (parent) {
          const parents = new Set(parent.parentPackages ?? []);
          parents.add(parentDependency.name);
          parent.parentPackages = [...parents];
          continue;
        }
        seen.add(key);
        const dependency: DependencyRecord = {
          name,
          declaredVersion,
          version: declaredVersion.match(/\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?/)?.[0] ?? 'unknown',
          scope: 'dependencies',
          parentPackages: [parentDependency.name],
        };
        result.push(dependency);
        recordsByName.set(key, dependency);
        next.push(dependency);
      }
    }
    frontier = next;
  }

  return result.sort((a, b) => a.name.localeCompare(b.name));
}
