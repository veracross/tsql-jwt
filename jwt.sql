----------------------------
-- XML to JSON Conversion --
----------------------------
if object_id('dbo.XmlToJson') is not null
  drop function dbo.XmlToJson
go

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

grant execute on dbo.XmlToJson to public

go

---------------------
-- HMAC Encryption --
---------------------
/*
	Copyright © 2012 Ryan Malayter. All Rights Reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	1. Redistributions of source code must retain the above copyright
	notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
	notice, this list of conditions and the following disclaimer in the
	documentation and/or other materials provided with the distribution.

	3. The name of the author may not be used to endorse or promote products
	derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY Ryan Malayter "AS IS" AND ANY EXPRESS OR
	IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
	INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
	HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
	STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
	ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

/* 
	This function only takes VARBINARY parameters instead of VARCHAR
	to prevent problems with implicit conversion from NVARCHAR to VARCHAR
	which result in incorrect hashes for inputs including non-ASCII characters.
	Always cast @key and @data parameters to VARBINARY when using this function.
	Tested against HMAC vectors for MD5 and SHA1 from RFC 2202
*/

/*
	List of secure hash algorithms (parameter @algo) supported by MSSQL
	version. This is what is passed to the HASHBYTES system function.
	Omit insecure hash algorithms such as MD2 through MD5
	2005-2008R2: SHA1
	2012-2016: SHA1 | SHA2_256 | SHA2_512
*/
create or alter function dbo.hmac (
	@key	varbinary(max),
	@data	varbinary(MAX),
	@algo	varchar(20)
)
returns varbinary(64)
as
begin
	declare @ipad	bigint
	declare @opad	bigint
	declare @i		varbinary(64)
	declare @o		varbinary(64)
	declare @pos	integer

	-- SQL 2005 only allows XOR operations on integer types, so use bigint and iterate 8 times
	set @ipad = cast(0x3636363636363636 as bigint) -- constants from HMAC definition
	set @opad = cast(0x5C5C5C5C5C5C5C5C as bigint)

	if len(@key) > 64 -- if the key is greater than 512 bits we hash it first per HMAC definition
		set @key = cast(hashbytes(@algo, @key) as binary (64))
	else
		set @key = cast(@key as binary (64)) -- otherwise pad it out to 512 bits with zeros

	set @pos = 1
	set @i = cast('' AS varbinary(64)) -- initialize as empty binary value

	while @pos <= 57
	begin
		set @i = @i + cast((substring(@key, @pos, 8) ^ @ipad) as varbinary(64))
		set @pos = @pos + 8
	end

	set @pos = 1
	set @o = cast('' as varbinary(64)) -- initialize as empty binary value

	while @pos <= 57
	begin
		set @o = @o + cast((substring(@key, @pos, 8) ^ @opad) as varbinary(64))
		set @pos = @pos + 8
	end

	return hashbytes(@algo, @o + hashbytes(@algo, @i + @data))
end
go

grant execute on dbo.HMAC to public
go

---------------------
-- Base64 Encoding --
---------------------
if object_id('dbo.Base64') is not null
  drop function dbo.Base64
go

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

grant execute on dbo.Base64 to public
go

-----------------------------
-- JSON Web Token Creation --
-----------------------------
create or alter function dbo.JWT_Encode(
	@json_header	varchar(max),
	@json_payload	varchar(max),
	@secret			varchar(max)
)
returns varchar(max)
as
begin

	declare @header		varchar(max),
			@data		varchar(max),
			@signature	varchar(max);

	-- Base64 encode json header
	select @header = dbo.Base64(convert(varbinary(max), @json_header), 1);

	-- Base64 encode json payload
	select @data = dbo.Base64(convert(varbinary(max), @json_payload), 1);

	-- Generate signature
	select	@signature = dbo.HMAC(convert(varbinary(max), @secret), convert(varbinary(max), @header + '.' + @data), 'SHA2_256');

	-- Base64 encode signature
	select	@signature = dbo.Base64(convert(varbinary(max), @signature), 1);

	return @header + '.' + @data + '.' + @signature;
end
go

grant execute on dbo.JWT_Encode to public
go

-------------------
-- Example Usage --
-------------------
select	dbo.JWT_Encode(
			dbo.XmlToJson((select 'HS256' alg, 'JWT' typ for xml path, root)),
			dbo.XmlToJson((select 'chris' name, 'true' admin for xml path, root)),
			'secret'
		)

select	dbo.JWT_Encode(
			(select 'HS256' alg, 'JWT' typ for json path, without_array_wrapper),
			(select 'brian' name, 'true' admin for json path, without_array_wrapper),
			'secret'
		)

select	dbo.JWT_Encode(
			'{"alg":"HS256","typ":"JWT"}',
			'{"name":"brian","admin":"true"}',
			'secret'
		)
