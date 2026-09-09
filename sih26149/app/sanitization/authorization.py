"""
Auditable Operator Authorization.
Requires explicit operator identity and scope acknowledgement.
No fake security tokens.
"""
from dataclasses import dataclass, asdict
from typing import Dict, Any


class UnauthorizedError(Exception):
    pass


@dataclass
class OperatorAuthorization:
    operator_id: str
    operator_name: str
    authorization_reason: str
    confirmed_scope_acknowledgement: bool

    def to_dict(self) -> dict:
        return asdict(self)


def authorize_sanitization(payload: Dict[str, Any]) -> OperatorAuthorization:
    """
    Validate operator authorization request.
    Enforces that operator identity is present and the technical scope limitation
    is explicitly acknowledged before any destruction or overwrite operation.
    """
    operator_id = str(payload.get('operator_id', '')).strip()
    operator_name = str(payload.get('operator_name', '')).strip()
    reason = str(payload.get('authorization_reason', '')).strip()
    scope_ack = payload.get('confirmed_scope_acknowledgement', False)

    if not operator_id or not operator_name:
        raise UnauthorizedError('Sanitization REJECTED: Operator credentials (ID and Name) are mandatory')

    if not reason:
        raise UnauthorizedError('Sanitization REJECTED: Legitimate operational authorization reason required')

    if scope_ack is not True:
        raise UnauthorizedError(
            'Sanitization REJECTED: Operator must explicitly acknowledge the technical scope '
            '(virtual filesystem/image overwrite only; does not guarantee physical NAND erasure)'
        )

    return OperatorAuthorization(
        operator_id=operator_id,
        operator_name=operator_name,
        authorization_reason=reason,
        confirmed_scope_acknowledgement=True,
    )
