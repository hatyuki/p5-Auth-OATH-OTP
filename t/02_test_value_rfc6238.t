use strict;
use warnings;
use Test::More;
use Auth::OATH::OTP;

subtest timestamp => sub {
    my $auth = Auth::OATH::OTP->new;
    is $auth->timestamp(         59), 0x00000001;
    is $auth->timestamp( 1111111109), 0x023523EC;
    is $auth->timestamp( 1111111111), 0x023523ED;
    is $auth->timestamp( 1234567890), 0x0273EF07;
    is $auth->timestamp( 2000000000), 0x03F940AA;
    is $auth->timestamp(20000000000), 0x27BC86AA;
};

subtest SHA1 => sub {
    my $secret = pack 'A*', '12345678901234567890';
    my $auth   = Auth::OATH::OTP->new(
        algorithm => 'Digest::SHA1',
        digits    => 8,
    );

    is $auth->totp($secret,          59), '94287082';
    is $auth->totp($secret,  1111111109), '07081804';
    is $auth->totp($secret,  1111111111), '14050471';
    is $auth->totp($secret,  1234567890), '89005924';
    is $auth->totp($secret,  2000000000), '69279037';
    is $auth->totp($secret, 20000000000), '65353130';
};

subtest SHA256 => sub {
    my $secret = pack 'A*', '12345678901234567890123456789012';
    my $auth   = Auth::OATH::OTP->new(
        algorithm => 'sha256',
        digits    => 8,
    );

    is $auth->totp($secret,          59), '46119246';
    is $auth->totp($secret,  1111111109), '68084774';
    is $auth->totp($secret,  1111111111), '67062674';
    is $auth->totp($secret,  1234567890), '91819424';
    is $auth->totp($secret,  2000000000), '90698825';
    is $auth->totp($secret, 20000000000), '77737706';
};

subtest SHA512 => sub {
    my $secret = pack 'A*', '1234567890123456789012345678901234567890123456789012345678901234';
    my $auth   = Auth::OATH::OTP->new(
        algorithm => 'sha512',
        digits    => 8,
    );

    is $auth->totp($secret,          59), '90693936';
    is $auth->totp($secret,  1111111109), '25091201';
    is $auth->totp($secret,  1111111111), '99943326';
    is $auth->totp($secret,  1234567890), '93441116';
    is $auth->totp($secret,  2000000000), '38618901';
    is $auth->totp($secret, 20000000000), '47863826';
};

done_testing;
