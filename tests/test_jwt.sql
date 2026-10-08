-- Expected tokens were generated with Python's hmac/base64 modules

declare @header varchar(max) = '{"alg":"HS256","typ":"JWT"}',
        @payload varchar(max) = '{"sub":"1234567890","name":"John Doe","iat":1516239022}',
        @token varchar(max) = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

insert tests.results select * from tests.assert_equal('JWT_Encode: jwt.io example', @token, dbo.JWT_Encode(@header, @payload, 'your-256-bit-secret'))
insert tests.results select * from tests.assert_equal('JWT_Decode: jwt.io example', @payload, dbo.JWT_Decode(@token, 'your-256-bit-secret'))
go

declare @token varchar(max) = dbo.JWT_Encode(
            (select 'HS256' alg, 'JWT' typ for json path, without_array_wrapper),
            (select 'Dwight' first_name, 'Assistant to Regional Manager' title for json path, without_array_wrapper),
            'super_secret_shhh'
        )

insert tests.results select * from tests.assert_equal('JWT_Encode: README example', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdF9uYW1lIjoiRHdpZ2h0IiwidGl0bGUiOiJBc3Npc3RhbnQgdG8gUmVnaW9uYWwgTWFuYWdlciJ9.WqUKx6U8gSumqEiGYJchQg42cis_NwVyKVRs3LSUGbY', @token)
insert tests.results select * from tests.assert_equal('JWT_Decode: README example', '{"first_name":"Dwight","title":"Assistant to Regional Manager"}', dbo.JWT_Decode(@token, 'super_secret_shhh'))
go

-- round trip payloads of every length mod 3, so every padding case is exercised
declare @header varchar(max) = '{"alg":"HS256","typ":"JWT"}',
        @payload varchar(max),
        @test_name varchar(200),
        @decoded varchar(max),
        @i int = 0

while @i < 6
begin
    select  @payload = '{"n":"' + replicate('x', @i) + '"}',
            @test_name = concat('JWT round trip: payload length ', len(@payload))
    select  @decoded = dbo.JWT_Decode(dbo.JWT_Encode(@header, @payload, 'secret'), 'secret')

    insert tests.results select * from tests.assert_equal(@test_name, @payload, @decoded)

    select @i = @i + 1
end

-- tokens over 8000 characters
select  @payload = '{"data":"' + replicate(convert(varchar(max), 'abcdefghij'), 10000) + '"}'
begin try
    select @decoded = dbo.JWT_Decode(dbo.JWT_Encode(@header, @payload, 'secret'), 'secret')
end try
begin catch
    select @decoded = error_message()
end catch
insert tests.results select * from tests.assert_equal('JWT round trip: 100KB payload', @payload, @decoded)

select  @decoded = dbo.JWT_Decode(dbo.JWT_Encode(@header, '{"a":1}', replicate('k', 100)), replicate('k', 100))
insert tests.results select * from tests.assert_equal('JWT round trip: secret longer than block size', '{"a":1}', @decoded)
go

-- Invalid tokens must be rejected

declare @invalid varchar(max) = '{"errorMessage":"Invalid Token", "errorCode":"500"}',
        @header varchar(max) = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        @payload varchar(max) = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
        @signature varchar(max) = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        @secret varchar(max) = 'your-256-bit-secret',
        @actual varchar(max)

select @actual = dbo.JWT_Decode(@header + '.' + @payload + '.' + @signature, 'wrong-secret')
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: wrong secret', @invalid, @actual)

-- payload changed to {"sub":"1234567890","name":"John Doe","iat":1516239023}
select @actual = dbo.JWT_Decode(@header + '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIzfQ.' + @signature, @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: tampered payload', @invalid, @actual)

select @actual = dbo.JWT_Decode(@header + '.' + @payload + '.' + upper(@signature), @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: signature with different case', @invalid, @actual)

select @actual = dbo.JWT_Decode(@header + '.' + @payload + '.' + lower(@signature), @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: signature with different case (lower)', @invalid, @actual)

select @actual = dbo.JWT_Decode(@header + '.' + @payload + '.' + @signature + ' ', @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: signature with trailing space', @invalid, @actual)

select @actual = dbo.JWT_Decode(@header + '.' + @payload, @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: missing signature', @invalid, @actual)

select @actual = dbo.JWT_Decode(@header + '.' + @payload + '.', @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: empty signature', @invalid, @actual)

select @actual = dbo.JWT_Decode(@header + '.' + @payload + '.' + @signature + '.extra', @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: extra segment', @invalid, @actual)

select @actual = dbo.JWT_Decode(@payload, @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: single segment', @invalid, @actual)

select @actual = dbo.JWT_Decode('', @secret)
insert tests.results select * from tests.assert_equal('JWT_Decode rejects: empty token', @invalid, @actual)
go

-- A token whose segments repeat must still be split in order
declare @token varchar(max) = dbo.JWT_Encode('{"a":1}', '{"a":1}', 'secret')
insert tests.results select * from tests.assert_equal('JWT_Decode: header equal to payload', '{"a":1}', dbo.JWT_Decode(@token, 'secret'))
go
