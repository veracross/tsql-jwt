create or alter function dbo.XmlToJson (
  @xmldata xml
)
returns nvarchar(max)
as
begin

    declare @json nvarchar(max)


    select  @json = concat(@json, ',{'
                    + stuff(
                        (
                            select ',"'
                                    + coalesce(b.c.value('local-name(.)', 'nvarchar(max)'), '')
                                    + '":"'
                                    + b.c.value('text()[1]','nvarchar(max)')
                                    + '"'

                            from    x.a.nodes('*') b(c)

                            for     xml path(''), type
                        ).value('(./text())[1]', 'nvarchar(max)')

                        , 1, 1, ''
                    )
                    + '}')

    from  @xmldata.nodes('/root/*') x(a)


    -- Remove leading comma
    return stuff(@json, 1, 1, '')

end
go

grant execute on dbo.XmlToJson to public
go
