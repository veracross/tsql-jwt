create or alter function dbo.Base64 (
    @data varbinary(max),
    @url_safe bit
)
returns varchar(max)
as
begin
    declare @base64string varchar(max)


    -- When converting a table to json, binary data in the table is converted to a BASE64 String
    select  @base64string = col

    from    openjson(
                (
                    select col
                    from (select @data col) T
                    for json auto
                )
            ) with(col varchar(max))


    if @url_safe = 1
    begin
        select @base64string = replace(@base64string, '+', '-')
        select @base64string = replace(@base64string, '/', '_')
    end


    return @base64string
end
go

grant execute on dbo.Base64 to public
go
