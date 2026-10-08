create or alter function dbo.Base64ToBinary (
  @data varchar(max),
  @url_safe bit
)
returns varbinary(max)
as
begin
    -- SQL Server 2025+: base64_decode accepts both the standard and url safe alphabets, with or
    -- without = padding, so @url_safe is no longer needed and is kept for backwards compatibility
    return base64_decode(@data)
end
go

grant execute on dbo.Base64ToBinary to public
go
