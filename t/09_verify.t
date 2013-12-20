use strict;
use warnings;
use Test::More;
use Auth::OATH::OTP::Verifier;

subtest TOTP => sub {
    my $oath = Auth::OATH::OTP::Verifier->new(
        types  => 'TOTP',
        window => 5,
        secret => 'A' x 32,
    );

    ok $oath->verify('887919', 90);
    ok $oath->verify('812658', 90);
    ok $oath->verify('073348', 90);
    ok $oath->verify('320986', 90);
    ok $oath->verify('435986', 90);
    ok not $oath->verify('328482', 90);
    ok not $oath->verify('964213', 90);
    ok not $oath->verify( );
    ok not $oath->verify(0);
};

subtest HOTP => sub {
    my $oath = Auth::OATH::OTP::Verifier->new(
        types  => 'HOTP',
        window => 5,
        secret => 'A' x 32,
    );
    ok $oath->verify('887919', 3);
    ok not $oath->verify('073348', 3);
    ok not $oath->verify('320986', 3);
    ok not $oath->verify(0, 1);
    eval { $oath->verify(0) };
    ok $@;
};

subtest Error => sub {
    my $oath = Auth::OATH::OTP::Verifier->new(types => 'Error');
    eval { $oath->verify(0) };
    ok $@;
};

done_testing;
