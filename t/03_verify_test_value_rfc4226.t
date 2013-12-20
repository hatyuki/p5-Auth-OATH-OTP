use strict;
use warnings;
use Test::More;
use Auth::OATH::OTP::Verifier;

my $auth = Auth::OATH::OTP::Verifier->new(
    secret => 'gezdgnbvgy3tqojqgezdgnbvgy3tqojq',
    types  => 'hotp',
);

ok $auth->verify('755224', 0);
ok $auth->verify('287082', 1);
ok $auth->verify('359152', 2);
ok $auth->verify('969429', 3);
ok $auth->verify('338314', 4);
ok $auth->verify('254676', 5);
ok $auth->verify('287922', 6);
ok $auth->verify('162583', 7);
ok $auth->verify('399871', 8);
ok $auth->verify('520489', 9);

done_testing;
