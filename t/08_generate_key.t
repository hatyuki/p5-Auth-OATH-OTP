use strict;
use warnings;
use Test::More;
use Auth::OATH::OTP::Verifier;

like Auth::OATH::OTP::Verifier::generate_secret_key(  ), qr/^[A-Z2-7]{32}$/;
like Auth::OATH::OTP::Verifier::generate_secret_key( 0), qr/^[A-Z2-7]{32}$/;
like Auth::OATH::OTP::Verifier::generate_secret_key(-1), qr/^[A-Z2-7]{32}$/;
like Auth::OATH::OTP::Verifier::generate_secret_key(16), qr/^[A-Z2-7]{16}$/;

done_testing;
