export type ReconcileFilter = { merchant: string; minAmount: number; maxAmount: number; from: string; to: string };
export function parseReconcileFilter(source: unknown): ReconcileFilter;
