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
            @signature_verify varchar(max)


    declare @token_components table (
        token_index int,
        token_value varchar(max)
    )


    insert  @token_components (token_index, token_value)

    select  token_index = row_number() over (order by patindex(value, @token)),
            token_value = value

    from    string_split(@token, '.');


    select @header = token_value from @token_components where token_index = 1
    select @payload = token_value from @token_components where token_index = 2
    select @signature = token_value from @token_components where token_index = 3


    select @signature_verify = dbo.Base64(dbo.HMAC(convert(varbinary(max), @secret), convert(varbinary(max), @header + '.' + @payload), 'SHA2_256'), 1)


    if @signature_verify != @signature
    begin
        return '{"errorMessage":"Invalid Token", "errorCode":"500"}'
    end


    return convert(varchar(max), dbo.Base64ToBinary(@payload, 1))
end
go


grant execute on dbo.JWT_Decode to public
go
