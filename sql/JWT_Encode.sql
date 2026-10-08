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
    select @header = base64_encode(convert(varbinary(max), @json_header), 1);

    -- Base64 encode json payload
    select @data = base64_encode(convert(varbinary(max), @json_payload), 1);

    -- Generate signature and Base64 encode it
    select @signature = base64_encode(dbo.HMAC(convert(varbinary(max), @secret), convert(varbinary(max), @header + '.' + @data), 'SHA2_256'), 1);

    return @header + '.' + @data + '.' + @signature;
end
go

grant execute on dbo.JWT_Encode to public
go
