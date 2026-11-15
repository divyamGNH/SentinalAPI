import { SimulationCase } from '../shared/simulation';
import { releaseDetectionState } from './detectionState';

const active = new Map<string, { userId: number; cases: Map<string, string>; controller: AbortController }>();
export function registerSimulation(id: string, userId: number, cases: SimulationCase[], controller: AbortController) {
  if ([...active.values()].some(run => run.userId === userId)) throw new Error('A simulation is already running for this user');
  if (active.size >= 4) throw new Error('The local lab already has four active simulations');
  active.set(id, { userId, cases: new Map(cases.map(item => [item.id, item.lane])), controller });
}
export function simulationLane(id: string, userId: number, caseId: string) {
  const run = active.get(id);
  return run?.userId === userId ? run.cases.get(caseId) : undefined;
}
export function stopSimulation(id: string) { active.get(id)?.controller.abort(); }
export function finishSimulation(id: string) { active.delete(id); releaseDetectionState(`simulation:${id}:`); }
