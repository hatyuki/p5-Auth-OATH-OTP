use strict;
use warnings;
use Test::More;
use Auth::OATH::OTP;
use Auth::OATH::OTP::Verifier;

subtest 'Auth::OATH::OTP' => sub {
    my $oath1 = Auth::OATH::OTP->new(digits => 10);
    isa_ok $oath1, 'Auth::OATH::OTP';
    is $oath1->digits, 10;

    my $oath2 = Auth::OATH::OTP->new( +{ digits => 20 } );
    isa_ok $oath2, 'Auth::OATH::OTP';
    is $oath2->digits, 20;

    my $oath3 = Auth::OATH::OTP->new(algorithm => '999');
    isa_ok $oath3, 'Auth::OATH::OTP';
    eval { $oath3->hmac('A', 'B') };
    ok $@;

    eval { Auth::OATH::OTP->new(digits => 5) };
    ok $@;
};

subtest 'Auth::OATH::OTP::Verifier' => sub {
    my $oath1 = Auth::OATH::OTP::Verifier->new(label => 'Hoge');
    isa_ok $oath1, 'Auth::OATH::OTP';
    isa_ok $oath1, 'Auth::OATH::OTP::Verifier';
    is $oath1->label, 'Hoge';

    my $oath2 = Auth::OATH::OTP::Verifier->new( +{ label => 'Fuga' } );
    isa_ok $oath2, 'Auth::OATH::OTP';
    isa_ok $oath2, 'Auth::OATH::OTP::Verifier';
    is $oath2->label, 'Fuga';
};

done_testing;
