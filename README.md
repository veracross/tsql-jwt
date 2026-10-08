# tsql-jwt
JSON Web Tokens in T-SQL for SQL Server

Requires SQL Server 2025 or later (uses the built-in `base64_encode` / `base64_decode` functions).
Tokens are signed and verified with HS256 (HMAC-SHA256).

# Example Usage

```sql
select  dbo.JWT_Encode(
            (select 'HS256' alg, 'JWT' typ for json path, without_array_wrapper), -- header
            (select 'Dwight' first_name, 'Assistant to Regional Manager' title for json path, without_array_wrapper), -- payload
            'super_secret_shhh' -- secret
        )

-- eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdF9uYW1lIjoiRHdpZ2h0IiwidGl0bGUiOiJBc3Npc3RhbnQgdG8gUmVnaW9uYWwgTWFuYWdlciJ9.WqUKx6U8gSumqEiGYJchQg42cis_NwVyKVRs3LSUGbY

select  dbo.JWT_Decode(
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdF9uYW1lIjoiRHdpZ2h0IiwidGl0bGUiOiJBc3Npc3RhbnQgdG8gUmVnaW9uYWwgTWFuYWdlciJ9.WqUKx6U8gSumqEiGYJchQg42cis_NwVyKVRs3LSUGbY', -- token
          'super_secret_shhh' -- secret
        )


-- {"first_name":"Dwight","title":"Assistant to Regional Manager"}

```

`JWT_Decode` returns `{"errorMessage":"Invalid Token", "errorCode":"500"}` when the token is malformed or its signature does not match.

# Development

Tests and benchmarks run against SQL Server 2025 in docker (`mcr.microsoft.com/mssql/server:2025-latest`).
On Apple silicon the image runs under emulation, so enable Rosetta in Docker Desktop.

```sh
scripts/run.sh up                       # start SQL Server and wait until it is healthy
scripts/run.sh test                     # deploy sql/ to a fresh database and run tests/test_*.sql
scripts/run.sh bench [git_ref] [label]  # deploy sql/ (from git_ref if given) and run bench/bench.sql
scripts/run.sh down                     # stop and remove the container
```

Benchmark results are appended to `bench/results.csv` (ignored by git), so runs of different versions can be compared.
