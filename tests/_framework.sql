/*
    Minimal assertion framework. Assertions are inline table-valued functions so that
    function calls can be passed directly as arguments:

        insert tests.results select * from tests.assert_equal('name', 'expected', dbo.Fn(...))

    tests/_report.sql prints the results and raises an error if anything failed.
*/
if schema_id('tests') is null
    exec('create schema tests')
go

drop table if exists tests.results
go

create table tests.results (
    test_name   varchar(200),
    passed      bit,
    expected    varchar(max),
    actual      varchar(max),
    id          int identity primary key
)
go

-- Strings are compared byte for byte so that case and trailing whitespace matter
create or alter function tests.assert_equal (
    @test_name  varchar(200),
    @expected   varchar(max),
    @actual     varchar(max)
)
returns table
as
return
    select  test_name = @test_name,
            passed = convert(bit, case
                when @expected is null and @actual is null then 1
                when convert(varbinary(max), @expected) = convert(varbinary(max), @actual) then 1
                else 0
            end),
            expected = @expected,
            actual = @actual
go

create or alter function tests.assert_equal_binary (
    @test_name  varchar(200),
    @expected   varbinary(max),
    @actual     varbinary(max)
)
returns table
as
return
    select  test_name = @test_name,
            passed = convert(bit, case
                when @expected is null and @actual is null then 1
                when @expected = @actual and datalength(@expected) = datalength(@actual) then 1
                else 0
            end),
            expected = convert(varchar(max), @expected, 1),
            actual = convert(varchar(max), @actual, 1)
go
