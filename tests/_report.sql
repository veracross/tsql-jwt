set nocount on

select  test_name,
        expected = left(expected, 100),
        actual = left(actual, 100)

from    tests.results

where   passed = 0

order by id


declare @passed int = (select count(*) from tests.results where passed = 1),
        @failed int = (select count(*) from tests.results where passed = 0)

print concat(@passed, ' passed, ', @failed, ' failed')

if @failed > 0
    raiserror('%d test(s) failed', 16, 1, @failed)
