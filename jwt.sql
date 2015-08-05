----------------------------
-- XML to JSON Conversion --
----------------------------
create function dbo.XmlToJson(@xmldata xml)
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

---------------------
-- HMAC Encryption --
---------------------
create function dbo.HMAC(
 @key   varchar(max),
 @message varchar(max),
 @method  varchar(20)
)
returns varchar(max)
as
begin

 declare @i_key_pad varchar(max)  = '';
 declare @o_key_pad varchar(max)  = '';
 declare @position  int   = 1;

 -- hash key if longer than 16 characters
 if(len(@key) > 64) set @key = hashbytes(@method, @key);

 -- splice ipad & opod with key
 while @position <= len(@key)
 begin
  set @i_key_pad = @i_key_pad + char(ascii(substring(@key, @position, 1)) ^ 54);
  set @o_key_pad = @o_key_pad + char(ascii(substring(@key, @position, 1)) ^ 92);
  set @position = @position + 1;
 end

 --pad i_key_pad & o_key_pad
 set @i_key_pad = left(@i_key_pad + replicate('6',64),64);
 set @o_key_pad = left(@o_key_pad + replicate('\',64),64);

 return hashbytes
  (
   @method,
   convert(varbinary(max), @o_key_pad)
    + hashbytes
    (
     @method,
     @i_key_pad + @message
    )
  );

end;

go

---------------------
-- Base64 Encoding --
---------------------
create function dbo.Base64(
  @data varbinary(max),
  @url_safe bit
)
returns varchar(max)
as
begin
  declare @base64string varchar(max)

  select @base64string = cast('' as xml).value('xs:base64Binary(sql:variable(''@data''))', 'varchar(max)')

  if @url_safe = 1
  begin
    select @base64string = replace(@base64string, '+', '-')
    select @base64string = replace(@base64string, '/', '_')
  end

  return @base64string
end

go

-----------------------------
-- JSON Web Token Creation --
-----------------------------
create function dbo.JWT_Encode(@header varchar(max), @payload varchar(max), @secret varchar(max))
returns varchar(max)
as
begin

  declare @h varchar(max),
          @d varchar(max),
          @sig varchar(max)

  select @h = dbo.Base64(convert(varbinary(max), @header), 1)

  select @d = dbo.Base64(convert(varbinary(max), @payload), 1)

  select @sig = dbo.Base64(convert(varbinary(max), dbo.HMAC(@secret, @h + '.' + @d, 'SHA2_256')), 1)

  return @h + '.' + @d + '.' + @sig
end

go

-------------------
-- Example Usage --
-------------------
select dbo.JWT_Encode(dbo.XmlToJson((select 'HS256' alg, 'JWT' typ for xml path, root)),
                      dbo.XmlToJson((select 'chris' name, 'true' admin for xml path, root)),
                      'secret')
