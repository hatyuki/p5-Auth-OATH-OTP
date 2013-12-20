use strict;
use warnings;
use utf8;
use Test::More;
use Auth::OATH::OTP::Verifier;

subtest TOTP => sub {
    my $oath = Auth::OATH::OTP::Verifier->new(
        label  => 'Hoge',
        secret => 'A' x 32,
        types  => 'TOTP',
    );
    is $oath->key_uri, 'otpauth://totp/Hoge?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
};

subtest HOTP => sub {
    my $oath = Auth::OATH::OTP::Verifier->new(
        label  => 'テスト',
        secret => 'A' x 32,
        types  => 'HOTP',
    );
    is $oath->key_uri, 'otpauth://hotp/%E3%83%86%E3%82%B9%E3%83%88?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
};

done_testing;
