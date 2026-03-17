create or alter function dbo.JWT_Encode (
    @json_header    varchar(max),
    @json_payload   varchar(max),
    @secret         varchar(max)
)
returns varchar(max)
as
begin

    declare @header     varchar(max),
            @data       varchar(max),
            @signature  varchar(max);

    -- Base64 encode json header
    select @header = dbo.Base64(convert(varbinary(max), @json_header), 1);

    -- Base64 encode json payload
    select @data = dbo.Base64(convert(varbinary(max), @json_payload), 1);

    -- Generate signature
    select @signature = dbo.HMAC(convert(varbinary(max), @secret), convert(varbinary(max), @header + '.' + @data), 'SHA2_256');

    -- Base64 encode signature
    select @signature = dbo.Base64(convert(varbinary(max), @signature), 1);

    return @header + '.' + @data + '.' + @signature;
end
go

grant execute on dbo.JWT_Encode to public
go
