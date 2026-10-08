create or alter function dbo.JWT_Decode (
    @token  varchar(max),
    @secret varchar(max)
)
returns varchar(max) -- returns a json string
as
begin
    declare @header varchar(max),
            @payload varchar(max),
            @signature varchar(max),
            @signature_verify varchar(max),
            @first_dot bigint,
            @second_dot bigint


    -- A token must have exactly three segments: header.payload.signature
    select @first_dot = charindex('.', @token)
    select @second_dot = charindex('.', @token, @first_dot + 1)

    if @first_dot = 0 or @second_dot = 0 or charindex('.', @token, @second_dot + 1) > 0
    begin
        return '{"errorMessage":"Invalid Token", "errorCode":"500"}'
    end


    select @header = substring(@token, 1, @first_dot - 1)
    select @payload = substring(@token, @first_dot + 1, @second_dot - @first_dot - 1)
    select @signature = substring(@token, @second_dot + 1, datalength(@token))


    select @signature_verify = dbo.Base64(dbo.HMAC(convert(varbinary(max), @secret), convert(varbinary(max), @header + '.' + @payload), 'SHA2_256'), 1)


    -- Compare as binary: string comparison is case insensitive under most collations and ignores trailing spaces
    if convert(varbinary(max), @signature) != convert(varbinary(max), @signature_verify)
        or datalength(@signature) != datalength(@signature_verify)
    begin
        return '{"errorMessage":"Invalid Token", "errorCode":"500"}'
    end


    return convert(varchar(max), dbo.Base64ToBinary(@payload, 1))
end
go


grant execute on dbo.JWT_Decode to public
go
