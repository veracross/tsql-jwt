# tsql-jwt
JSON Web Tokens in T-SQL for SQL Server

# Example Usage

```sql
select  dbo.JWT_Encode(
            (select 'HS256' alg, 'JWT' typ for json path, without_array_wrapper), -- header
            (select 'Dwight' first_name, 'Assistant to Regional Manager' title for json path, without_array_wrapper), -- payload
            'super_secret_shhh' -- secret
        )

-- eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdF9uYW1lIjoiRHdpZ2h0IiwidGl0bGUiOiJBc3Npc3RhbnQgdG8gUmVnaW9uYWwgTWFuYWdlciJ9.WqUKx6U8gSumqEiGYJchQg42cis_NwVyKVRs3LSUGbY=

select  dbo.JWT_Decode(
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdF9uYW1lIjoiRHdpZ2h0IiwidGl0bGUiOiJBc3Npc3RhbnQgdG8gUmVnaW9uYWwgTWFuYWdlciJ9.WqUKx6U8gSumqEiGYJchQg42cis_NwVyKVRs3LSUGbY=', -- token
          'super_secret_shhh' -- secret
        )


-- {"first_name":"Dwight","title":"Assistant to Regional Manager"}

```
