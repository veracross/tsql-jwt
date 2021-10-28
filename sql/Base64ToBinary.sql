create or alter function dbo.Base64ToBinary (
  @data varchar(max),
  @url_safe bit
)
returns varbinary(max)
as
begin
    declare @binaryData varbinary(max)


    if @url_safe = 1
    begin
        select @data = replace(@data, '-', '+')
        select @data = replace(@data, '_', '/')
    end


    select  @binaryData = col

    from    openjson(
                (
                    select col
                    from (select @data col) T
                    for json auto
                )
            ) with(col varbinary(max))


    return @binaryData
end
go

grant execute on dbo.Base64ToBinary to public
go
