-- RFC 4648 section 10 test vectors, plus inputs that exercise the url-safe alphabet

insert tests.results select * from tests.assert_equal('Base64: empty', '', dbo.Base64(0x, 0))
insert tests.results select * from tests.assert_equal('Base64: f', 'Zg==', dbo.Base64(0x66, 0))
insert tests.results select * from tests.assert_equal('Base64: fo', 'Zm8=', dbo.Base64(0x666F, 0))
insert tests.results select * from tests.assert_equal('Base64: foo', 'Zm9v', dbo.Base64(0x666F6F, 0))
insert tests.results select * from tests.assert_equal('Base64: foob', 'Zm9vYg==', dbo.Base64(0x666F6F62, 0))
insert tests.results select * from tests.assert_equal('Base64: fooba', 'Zm9vYmE=', dbo.Base64(0x666F6F6261, 0))
insert tests.results select * from tests.assert_equal('Base64: foobar', 'Zm9vYmFy', dbo.Base64(0x666F6F626172, 0))
insert tests.results select * from tests.assert_equal('Base64: + and /', '+/8=', dbo.Base64(0xFBFF, 0))
insert tests.results select * from tests.assert_equal('Base64: null', null, dbo.Base64(null, 0))

insert tests.results select * from tests.assert_equal('Base64 url safe: f', 'Zg', dbo.Base64(0x66, 1))
insert tests.results select * from tests.assert_equal('Base64 url safe: fo', 'Zm8', dbo.Base64(0x666F, 1))
insert tests.results select * from tests.assert_equal('Base64 url safe: foobar', 'Zm9vYmFy', dbo.Base64(0x666F6F626172, 1))
insert tests.results select * from tests.assert_equal('Base64 url safe: - and _', '-_8', dbo.Base64(0xFBFF, 1))
insert tests.results select * from tests.assert_equal('Base64 url safe: - and _ no padding', '-_-_', dbo.Base64(0xFBFFBF, 1))

declare @large varbinary(max) = convert(varbinary(max), replicate(convert(varchar(max), 'abc'), 100000))
insert tests.results select * from tests.assert_equal('Base64: 300KB', replicate(convert(varchar(max), 'YWJj'), 100000), dbo.Base64(@large, 0))
go

insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: empty', 0x, dbo.Base64ToBinary('', 0))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: f', 0x66, dbo.Base64ToBinary('Zg==', 0))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: fo', 0x666F, dbo.Base64ToBinary('Zm8=', 0))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: foo', 0x666F6F, dbo.Base64ToBinary('Zm9v', 0))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: foob', 0x666F6F62, dbo.Base64ToBinary('Zm9vYg==', 0))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: fooba', 0x666F6F6261, dbo.Base64ToBinary('Zm9vYmE=', 0))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: foobar', 0x666F6F626172, dbo.Base64ToBinary('Zm9vYmFy', 0))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: + and /', 0xFBFF, dbo.Base64ToBinary('+/8=', 0))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: null', null, dbo.Base64ToBinary(null, 0))

insert tests.results select * from tests.assert_equal_binary('Base64ToBinary url safe: f', 0x66, dbo.Base64ToBinary('Zg', 1))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary url safe: fo', 0x666F, dbo.Base64ToBinary('Zm8', 1))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary url safe: foobar', 0x666F6F626172, dbo.Base64ToBinary('Zm9vYmFy', 1))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary url safe: - and _', 0xFBFF, dbo.Base64ToBinary('-_8', 1))
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary url safe: - and _ no padding', 0xFBFFBF, dbo.Base64ToBinary('-_-_', 1))

declare @large varchar(max) = replicate(convert(varchar(max), 'YWJj'), 100000)
insert tests.results select * from tests.assert_equal_binary('Base64ToBinary: 300KB', convert(varbinary(max), replicate(convert(varchar(max), 'abc'), 100000)), dbo.Base64ToBinary(@large, 0))
go

-- round trip every possible byte value, at each length mod 3
declare @all_bytes varbinary(max) = 0x
declare @i int = 0
while @i < 256
begin
    select @all_bytes = @all_bytes + convert(binary(1), @i)
    select @i = @i + 1
end

declare @all_bytes_1 varbinary(max) = substring(@all_bytes, 1, 255),
        @all_bytes_2 varbinary(max) = substring(@all_bytes, 1, 254)

insert tests.results select * from tests.assert_equal_binary('Base64 round trip: all bytes', @all_bytes, dbo.Base64ToBinary(dbo.Base64(@all_bytes, 0), 0))
insert tests.results select * from tests.assert_equal_binary('Base64 round trip url safe: all bytes', @all_bytes, dbo.Base64ToBinary(dbo.Base64(@all_bytes, 1), 1))
insert tests.results select * from tests.assert_equal_binary('Base64 round trip url safe: all bytes - 1', @all_bytes_1, dbo.Base64ToBinary(dbo.Base64(@all_bytes_1, 1), 1))
insert tests.results select * from tests.assert_equal_binary('Base64 round trip url safe: all bytes - 2', @all_bytes_2, dbo.Base64ToBinary(dbo.Base64(@all_bytes_2, 1), 1))
go
