from __future__ import annotations

import json
import os
import sys
import time

mode = sys.argv[1]
request_line = sys.stdin.read()

if mode == "sleep":
    time.sleep(2)
    raise SystemExit(0)

request = json.loads(request_line)

if mode == "echo":
    response = {
        "request_id": request["request_id"],
        "response": {"payload": request["payload"], "role": request["role"]},
    }
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
elif mode == "environment":
    response = {
        "request_id": request["request_id"],
        "response": {"model_id": os.environ.get("FALSIQ_MODEL_ID")},
    }
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
elif mode == "wrong-id":
    print('{"request_id":"another-request","response":{}}')
elif mode == "no-newline":
    sys.stdout.write('{"request_id":"request-1","response":{}}')
elif mode == "two-lines":
    print('{"request_id":"request-1","response":{}}')
    print("agent debug output that is not protocol")
elif mode == "malformed":
    print("not json")
elif mode == "invalid-schema":
    print('{"request_id":"request-1","response":{},"extra":"not allowed"}')
elif mode == "fail-with-secret":
    print("credential=stdout-super-secret")
    print("credential=stderr-super-secret", file=sys.stderr)
    raise SystemExit(9)
elif mode in {"oversized-stdout", "oversized-stderr"}:
    size = int(sys.argv[2])
    secret = f"credential={mode}-super-secret"
    stream = sys.stdout.buffer if mode == "oversized-stdout" else sys.stderr.buffer
    stream.write(secret.encode("utf-8") + b"x" * size)
    stream.flush()
    time.sleep(5)
elif mode == "sized-response":
    size = int(sys.argv[2])
    prefix = ('{"request_id":"' + request["request_id"] + '","response":{"padding":"').encode(
        "utf-8"
    )
    suffix = b'"}}\n'
    padding_size = size - len(prefix) - len(suffix)
    if padding_size < 0:
        raise AssertionError("requested response size is too small")
    sys.stdout.buffer.write(prefix + b"x" * padding_size + suffix)
    sys.stdout.buffer.flush()
else:
    raise AssertionError(f"unknown fake-agent mode: {mode}")
