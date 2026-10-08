create or alter function dbo.Base64 (
    @data varbinary(max),
    @url_safe bit
)
returns varchar(max)
as
begin
    -- SQL Server 2025+: url safe encoding uses - and _ in place of + and / and omits the = padding
    return base64_encode(@data, @url_safe)
end
go

grant execute on dbo.Base64 to public
go
