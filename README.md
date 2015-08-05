# tsql-jwt
JSON Web Tokens in T-SQL for SQL Server

# Example Usage
```sql
select dbo.JWT_Encode(dbo.XmlToJson((select 'HS256' alg, 'JWT' typ for xml path, root)),
                      dbo.XmlToJson((select 'chris' name, 'true' admin for xml path, root)),
                      'secret')
```
