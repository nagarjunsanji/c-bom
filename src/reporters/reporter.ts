import type { Cbom } from '../types';

export interface Reporter {
  readonly id: string;
  readonly fileName: string;
  render(cbom: Cbom): string;
}
