use strict;
use warnings;
use utf8;
use Test::More;
use Auth::OATH::OTP::Verifier;

subtest TOTP => sub {
    my $oath = Auth::OATH::OTP::Verifier->new(
        label  => 'Hoge',
        secret => 'A' x 32,
        issuer => 'Fuga',
        types  => 'TOTP',
    );
    is $oath->key_uri, 'otpauth://totp/Hoge?issuer=Fuga&secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
};

subtest HOTP => sub {
    my $oath = Auth::OATH::OTP::Verifier->new(
        label  => 'ほげ',
        secret => 'A' x 32,
        issuer => 'ふが',
        types  => 'HOTP',
    );
    is $oath->key_uri, 'otpauth://hotp/%E3%81%BB%E3%81%92?issuer=%E3%81%B5%E3%81%8C&secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
};

done_testing;
