import { useOperator } from './auth';
import { Customers } from './customers';
import { CustomerDevices } from './customer-devices';

/** Display metadata controls mounting only; the server checks every request. */
export function CustomerRecords({ revision }: { revision: number }) {
    const operator = useOperator();
    if (!operator?.authenticated || operator.checkingAccess || operator.hasExplicitMetadata !== true || !operator.expiresAt) return null;
    const shared = operator.loginMode === 'shared';
    const namedRead = operator.loginMode === 'named' && operator.capabilities?.includes('read_customers') === true;
    if (!shared && !namedRead) return null;
    const key = `${operator.actorId}:${operator.expiresAt}:${revision}`;
    return <>
        <Customers key={`customers:${key}`} sessionExpiresAt={operator.expiresAt} readOnly={!shared}/>
        <CustomerDevices key={`customer-devices:${key}`} sessionExpiresAt={operator.expiresAt} readOnly={!shared}/>
    </>;
}
