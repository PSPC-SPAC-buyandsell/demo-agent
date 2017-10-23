from binascii import b2a_hex
from functools import wraps

import json


def ppjson(dumpit):
    """
    JSON pretty printer, whether already json-encoded or not
    """

    return json.dumps(json.loads(dumpit) if isinstance(dumpit, str) else dumpit, indent=4)


def claim_value_pair(value):
    """
    Encoder for raw values in claims, returns pair with stringified and encoded-to-int values
    """

    s = str(value)
    return [
        s,
        s if s.isdigit() else str(int.from_bytes(b2a_hex(s.encode()), 'big'))
    ]


def plain_claims_for(claims: dict, filt: dict = {}) -> dict:
    """
    Find claims matching input attribute-value dict from within input claims structure,
    json-loaded as returned via agent get_claims().
    
    The input claims holds claims with values encoded to numeric strings as per
    claim_value_pair() above; this utility chooses only those matching the input original
    (non-encoded) value, replacing any values for attributes in the filter with their
    respective plain (non-encoded) values for more cogent display.

    :param claims: claims structure via get_claims();
        e.g., {
            "attrs": {
                "attr0_uuid": [
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "8080189724314",
                            "attr2": "110838914834142413139418734819234123943712834123947912834701743281470"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    },
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "8080189724314",
                            "attr2": "1"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    }
                ],
                "attr1_uuid": [
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "8080189724314",
                            "attr2": "110838914834142413139418734819234123943712834123947912834701743281470"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    },
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "8080189724314",
                            "attr2": "1"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    }
                ],
                "attr2_uuid": [
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-000000000000",
                        "attrs": {
                            "attr0": "2",
                            "attr1": "8080189724314",
                            "attr2": "110838914834142413139418734819234123943712834123947912834701743281470"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    },
                    {
                        "claim_uuid": "claim::00000000-0000-0000-0000-111111111111",
                        "attrs": {
                            "attr0": "1",
                            "attr1": "8080189724314",
                            "attr2": "1"
                        },
                        "issuer_did": "Q4zqM7aXqm7gDQkUVLng9h",
                        "schema_seq_no": 21
                    }
                ]
            }
        }
    :param filt: attributes and values to match from claims structure
    :return: dict mapping claim uuid to claim attributes for claims matching input filter. This returned structure
        is suitable for display and human inference, not for re-use in further protocol operations, since it
        presents any filter attributes as plain, pre-encoding values that the indy-sdk does not recognize.
    """
    uuid2claims = claims['attrs']
    encfilt = {k: claim_value_pair(filt[k])[1] for k in filt}
    matches = {}
    for claims in uuid2claims.values():
        for claim in claims:
            if claim['claim_uuid'] not in matches and (encfilt.items() <= claim['attrs'].items()):
                matches[claim['claim_uuid']] = {k: filt[k] if k in filt else claim['attrs'][k] for k in claim['attrs']}
    return matches


def prune_claims_json(claim_uuids: set, claims: dict) -> str:
    """
    Strips all claims out of the input json structure that do not match any of the input claim uuids

    :param claim_uuids: the set of claim uuids, as specified in claims json structure returned from get_claims,
        showing up as dict keys that claims_for_value() returns
    :param claims: claims structure returned by get_claims()
    :return: the reduced claims json
    """

    for attr_uuid, claims_by_uuid in claims['attrs'].items():
        claims['attrs'][attr_uuid] = [claim for claim in claims_by_uuid if claim['claim_uuid'] in claim_uuids]

    return json.dumps(claims)
