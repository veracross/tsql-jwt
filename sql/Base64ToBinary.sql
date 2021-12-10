create or alter function dbo.Base64ToBinary (
  @data varchar(max),
  @url_safe bit
)
returns varbinary(max)
as
begin
    declare @binary_data varbinary(max)


    if @url_safe = 1
    begin
        select @data = replace(@data, '-', '+')
        select @data = replace(@data, '_', '/')
    end


    select  @binary_data = col

    from    openjson(
                (
                    select col
                    from (select @data col) T
                    for json auto
                )
            ) with(col varbinary(max))


    return @binary_data
end
go

grant execute on dbo.Base64ToBinary to public
go
