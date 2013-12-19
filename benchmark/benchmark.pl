#!/usr/bin/env perl
use strict;
use warnings;
use Auth::OATH::OTP;
use Authen::OATH;
use Benchmark qw/ cmpthese timethese /;

my $secret = pack 'A*', '12345678901234567890';
my $this = Auth::OATH::OTP->new;
my $that = Authen::OATH->new;

die if $this->totp($secret) ne $that->totp($secret);

cmpthese timethese 100000, +{
    'Auth::OATH::OTP' => sub {
        my $oath = Auth::OATH::OTP->new;
        $oath->totp($secret);
    },
    'Authen::OATH' => sub {
        my $oath = Authen::OATH->new;
        $oath->totp($secret);
    },
    'Auth::OATH::OTP (reuse)' => sub {
        $this->totp($secret);
    },
    'Authen::OATH (reuse)' => sub {
        $that->totp($secret);
    },
};

__END__

Auth::OATH::OTP:  4 wallclock secs ( 3.86 usr +  0.01 sys =  3.87 CPU) @ 25839.79/s (n=100000)
Auth::OATH::OTP (reuse):  4 wallclock secs ( 3.58 usr +  0.02 sys =  3.60 CPU) @ 27777.78/s (n=100000)
Authen::OATH: 33 wallclock secs (33.38 usr +  0.05 sys = 33.43 CPU) @ 2991.33/s (n=100000)
Authen::OATH (reuse): 12 wallclock secs (11.84 usr +  0.03 sys = 11.87 CPU) @ 8424.60/s (n=100000)
                           Rate Authen::OATH Authen::OATH (reuse) Auth::OATH::OTP Auth::OATH::OTP (reuse)
Authen::OATH             2991/s           --                 -64%            -88%                    -89%
Authen::OATH (reuse)     8425/s         182%                   --            -67%                    -70%
Auth::OATH::OTP         25840/s         764%                 207%              --                     -7%
Auth::OATH::OTP (reuse) 27778/s         829%                 230%              8%                      --
