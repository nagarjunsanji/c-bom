import type { Cbom } from '../types';
import type { Reporter } from './reporter';

export const jsonReporter: Reporter = {
  id: 'json',
  fileName: 'cbom.json',
  render(cbom: Cbom): string {
    return `${JSON.stringify(cbom, null, 2)}\n`;
  },
};
