# Pulp-ext-entropy

CSPRNG capability for Pulp cells. Exposes `crypto/rand` via the `entropy.read` host import.

From [BananaLabs OSS](https://github.com/BananaLabs-OSS).

## Deployment

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-entropy"
```

## Capability

- `entropy.read` — `entropy_read(req_ptr, req_len, resp_ptr_out, resp_len_out) → errcode`
  - Request: `{"n": uint32}` (1–65536 bytes)
  - Response: `{"bytes": []byte}`
