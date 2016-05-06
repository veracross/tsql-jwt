
----------------------------
-- String Split function  --
----------------------------


if object_id('dbo.fn_Split') is not null
  drop function dbo.fn_Split
go


CREATE FUNCTION [dbo].[fn_Split] (@List varchar(max), @Delimiter varchar(5))
	RETURNS @TableOfValues table (RowID smallint IDENTITY(1,1), [Value] varchar(max))
AS
BEGIN

DECLARE @LenString int

WHILE LEN(@List) > 0 BEGIN
	SELECT @LenString =
    (
		CASE CHARINDEX(@Delimiter, @List )
			WHEN 0 THEN LEN(@List)
			ELSE (CHARINDEX(@Delimiter, @List)-1)
		END
	)

	INSERT INTO @TableOfValues
    SELECT SUBSTRING(@List, 1, @LenString)

    SELECT @List =
		(
			CASE (LEN(@List)-@LenString)
				WHEN 0 THEN ''
				ELSE RIGHT(@List,LEN(@List)-@LenString - 1)
			END
		)

	END

RETURN

END





----------------------------
-- XML to JSON Conversion --
----------------------------
if object_id('dbo.fn_XmlToJson') is not null
  drop function dbo.fn_XmlToJson
go

create function dbo.fn_XmlToJson(@xmldata xml)
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

grant execute on dbo.fn_XmlToJson to public

go

---------------------
-- HMAC Encryption --
---------------------
if object_id('dbo.fn_HMAC') is not null
  drop function dbo.fn_HMAC
go

create function dbo.fn_HMAC(
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

grant execute on dbo.fn_HMAC to public

go

---------------------
-- Base64 Encoding --
---------------------
if object_id('dbo.fn_Base64') is not null
  drop function dbo.fn_Base64
go

create function dbo.fn_Base64(
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

grant execute on dbo.fn_Base64 to public

go



----------------------
-- Base64 to Binary --
----------------------
if object_id('dbo.fn_Base64ToBinary') is not null
  drop function dbo.fn_Base64ToBinary
go

create function dbo.fn_Base64ToBinary(
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


  select @binaryData = cast(N'' as xml).value('xs:base64Binary(sql:variable("@data"))', 'varbinary(MAX)')


  return @binaryData
end

go

grant execute on dbo.fn_Base64ToBinary to public

go

-----------------------------
-- JSON Web Token Creation --
-----------------------------
if object_id('dbo.fn_JWT_Encode') is not null
  drop function dbo.fn_JWT_Encode
go

create function dbo.fn_JWT_Encode(@header varchar(max), @payload varchar(max), @secret varchar(max))
returns varchar(max)
as
begin

  declare @h varchar(max),
          @d varchar(max),
          @sig varchar(max)

  select @h = dbo.fn_Base64(convert(varbinary(max), @header), 1)

  select @d = dbo.fn_Base64(convert(varbinary(max), @payload), 1)

  select @sig = dbo.fn_Base64(convert(varbinary(max), dbo.fn_HMAC(@secret, @h + '.' + @d, 'SHA2_256')), 1)

  return @h + '.' + @d + '.' + @sig
end

go

grant execute on dbo.fn_JWT_Encode to public

go



-----------------------------
-- JSON Web Token Decode --
-----------------------------
if object_id('dbo.fn_JWT_Decode') is not null
  drop function dbo.fn_JWT_Decode
go

create function dbo.fn_JWT_Decode(@token varchar(max),@secret varchar(max))
	returns varchar(max) -- returns a json string
as
begin

  declare @header varchar(max),
          @payload varchar(max),
          @signature varchar(max),
          @signature_verify varchar(max)

  select @header = [value] from dbo.fn_split(@token,'.') where rowID = 1
  select @payload = [value] from dbo.fn_split(@token,'.') where rowID = 2
  select @signature = [value] from dbo.fn_split(@token,'.') where rowID = 3

  select @signature_verify = dbo.fn_Base64(convert(varbinary(max), dbo.fn_HMAC(@secret, @header + '.' + @payload, 'SHA2_256')), 1)

  select @payload = convert(varchar(max), dbo.fn_Base64ToBinary(@payload, 1) )

	if @signature_verify != @signature
		BEGIN

			select @payload = '{"errorMessage":"Invalid Token", "errorCode":"500"}'

		END

  return @payload
end

go

grant execute on dbo.fn_JWT_Decode to public

go


-------------------
-- Example Usage --
-------------------
/*
select dbo.fn_JWT_Encode(dbo.fn_XmlToJson((select 'HS256' alg, 'JWT' typ for xml path, root)),
                      dbo.fn_XmlToJson((select 'chris' name, 'true' admin for xml path, root)),
                      'secret')
*/
