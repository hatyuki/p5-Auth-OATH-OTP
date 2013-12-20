use strict;
use warnings;
use Test::More;
use Test::MockTime ( );
use Auth::OATH::OTP;

my $oath = Auth::OATH::OTP->new(timestep => 10);
is $oath->timestamp(100), 10;

Test::MockTime::set_absolute_time(35);
is $oath->timestamp, 3;

done_testing;
