use strict;
use warnings;
use Test::More;
use Auth::OATH::OTP::Verifier;

subtest SHA1 => sub {
    my $secret = pack 'A*', '12345678901234567890';
    my $auth   = Auth::OATH::OTP::Verifier->new(
        algorithm => 'Digest::SHA1',
        digits    => 8,
        binkey    => $secret,
    );

    ok $auth->verify('94287082',          59);
    ok $auth->verify('07081804',  1111111109);
    ok $auth->verify('14050471',  1111111111);
    ok $auth->verify('89005924',  1234567890);
    ok $auth->verify('69279037',  2000000000);
    ok $auth->verify('65353130', 20000000000);
};

subtest SHA256 => sub {
    my $secret = pack 'A*', '12345678901234567890123456789012';
    my $auth   = Auth::OATH::OTP::Verifier->new(
        algorithm => 'sha256',
        digits    => 8,
        binkey    => $secret,
    );

    ok $auth->verify('46119246',          59);
    ok $auth->verify('68084774',  1111111109);
    ok $auth->verify('67062674',  1111111111);
    ok $auth->verify('91819424',  1234567890);
    ok $auth->verify('90698825',  2000000000);
    ok $auth->verify('77737706', 20000000000);
};

subtest SHA512 => sub {
    my $secret = pack 'A*', '1234567890123456789012345678901234567890123456789012345678901234';
    my $auth   = Auth::OATH::OTP::Verifier->new(
        algorithm => 'sha512',
        digits    => 8,
        binkey    => $secret,
    );

    ok $auth->verify('90693936',          59);
    ok $auth->verify('25091201',  1111111109);
    ok $auth->verify('99943326',  1111111111);
    ok $auth->verify('93441116',  1234567890);
    ok $auth->verify('38618901',  2000000000);
    ok $auth->verify('47863826', 20000000000);
};

done_testing;
