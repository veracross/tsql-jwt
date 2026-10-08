/*
    Benchmarks for the JWT functions. Run with scripts/run.sh bench [git_ref] [label].

    Each case is run once to warm up and then @runs times; the median elapsed time is reported.
    Output rows prefixed with "bench," are appended to bench/results.csv:

        label, case, calls, median_ms, us_per_call
*/
set nocount on

declare @label varchar(100) = '$(label)',
        @rows int = 2000,       -- rows for set-based cases
        @loop_rows int = 500,   -- calls for row-by-row cases
        @runs int = 5

drop table if exists #payloads
drop table if exists #timings

create table #payloads (
    id          int primary key,
    header      varchar(max),
    payload     varchar(max),
    secret      varchar(max),
    token       varchar(max),
    signed_data varbinary(max),
    encoded     varchar(max)
)

create table #timings (
    case_name   varchar(100),
    calls       int,
    run         int,
    elapsed_us  bigint
)

-- typical small JWT payloads, each one different so nothing can be cached
;with n as (
    select top (@rows) id = row_number() over (order by (select null))
    from sys.all_objects a cross join sys.all_objects b
)
insert  #payloads (id, header, payload, secret)

select  id,
        '{"alg":"HS256","typ":"JWT"}',
        (select     sub = concat('user-', id),
                    name = concat('Test User ', id),
                    email = concat('user', id, '@example.com'),
                    roles = json_query('["reader","writer"]'),
                    iat = 1700000000 + id,
                    exp = 1700003600 + id
         for json path, without_array_wrapper),
        concat('secret-', id, '-0123456789abcdefghijklmnopqrstuvwxyz')

from    n

update  #payloads
set     token = dbo.JWT_Encode(header, payload, secret),
        signed_data = convert(varbinary(max), payload)

update  #payloads
set     encoded = dbo.Base64(signed_data, 1)


declare @cases table (
    case_name   varchar(100),
    calls       int,
    sql         nvarchar(max)
)

insert  @cases (case_name, calls, sql)

values  ('JWT_Encode set', @rows,
            N'select @out = max(len(dbo.JWT_Encode(header, payload, secret))) from #payloads option (maxdop 1)'),
        ('JWT_Decode set', @rows,
            N'select @out = max(len(dbo.JWT_Decode(token, secret))) from #payloads option (maxdop 1)'),
        ('HMAC set', @rows,
            N'select @out = max(datalength(dbo.HMAC(convert(varbinary(max), secret), signed_data, ''SHA2_256''))) from #payloads option (maxdop 1)'),
        ('Base64 set', @rows,
            N'select @out = max(len(dbo.Base64(signed_data, 1))) from #payloads option (maxdop 1)'),
        ('Base64ToBinary set', @rows,
            N'select @out = max(datalength(dbo.Base64ToBinary(encoded, 1))) from #payloads option (maxdop 1)'),
        ('JWT_Encode loop', @loop_rows,
            N'declare @i int = 1, @h varchar(max), @p varchar(max), @s varchar(max)
              while @i <= ' + convert(nvarchar(10), @loop_rows) + N'
              begin
                  select @h = header, @p = payload, @s = secret from #payloads where id = @i
                  select @out = len(dbo.JWT_Encode(@h, @p, @s))
                  select @i = @i + 1
              end'),
        ('JWT_Decode loop', @loop_rows,
            N'declare @i int = 1, @t varchar(max), @s varchar(max)
              while @i <= ' + convert(nvarchar(10), @loop_rows) + N'
              begin
                  select @t = token, @s = secret from #payloads where id = @i
                  select @out = len(dbo.JWT_Decode(@t, @s))
                  select @i = @i + 1
              end'),
        -- the largest token the original JWT_Decode can handle is just under 8000 characters
        ('JWT_Decode 5KB payload loop', 100,
            N'declare @i int = 1, @t varchar(max) = dbo.JWT_Encode(''{"alg":"HS256","typ":"JWT"}'', ''{"data":"'' + replicate(''abcdefghij'', 500) + ''"}'', ''secret'')
              while @i <= 100
              begin
                  select @out = len(dbo.JWT_Decode(@t, ''secret''))
                  select @i = @i + 1
              end')


declare @case_name varchar(100), @calls int, @sql nvarchar(max), @run int, @start datetime2(7), @out bigint

declare cases cursor local fast_forward for
    select case_name, calls, sql from @cases

open cases
fetch next from cases into @case_name, @calls, @sql

while @@fetch_status = 0
begin
    select @run = 0

    while @run <= @runs
    begin
        select @start = sysdatetime()
        exec sp_executesql @sql, N'@out bigint output', @out output

        if @run > 0 -- run 0 is a warm up
            insert #timings (case_name, calls, run, elapsed_us)
            values (@case_name, @calls, @run, datediff_big(microsecond, @start, sysdatetime()))

        select @run = @run + 1
    end

    fetch next from cases into @case_name, @calls, @sql
end

close cases
deallocate cases


select  distinct
        'bench',
        @label,
        case_name,
        calls,
        median_ms = convert(decimal(12, 1), percentile_cont(0.5) within group (order by elapsed_us) over (partition by case_name) / 1000.0),
        us_per_call = convert(decimal(12, 1), percentile_cont(0.5) within group (order by elapsed_us) over (partition by case_name) / calls)

from    #timings
