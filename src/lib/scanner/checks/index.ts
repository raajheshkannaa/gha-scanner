import { CheckDefinition } from '../types';
import { supplyChainChecks } from './supply-chain';
import { injectionChecks } from './injection';
import { dangerousTriggersChecks } from './dangerous-triggers';
import { permissionsChecks } from './permissions';
import { secretsExposureChecks } from './secrets-exposure';
import { runnerSecurityChecks } from './runner-security';
import { ciCdHygieneChecks } from './ci-cd-hygiene';
import { bestPracticesChecks } from './best-practices';

/**
 * How to add a new check:
 * 1. Add a CheckDefinition object to the appropriate category file
 * 2. Use semantic ID format: "category/check-name"
 * 3. Implement the `run` function that takes RepoContext and returns Finding[]
 * 4. The check is automatically included via the category's exported array
 */
export const allChecks: CheckDefinition[] = [
  ...supplyChainChecks,
  ...injectionChecks,
  ...dangerousTriggersChecks,
  ...permissionsChecks,
  ...secretsExposureChecks,
  ...runnerSecurityChecks,
  ...ciCdHygieneChecks,
  ...bestPracticesChecks,
];
